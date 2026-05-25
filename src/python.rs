#![cfg(feature = "python")]
// Raw-pointer casts in pyo3 macro expansions. Per-fn `#[allow]` doesn't reach
// the generated wrapper, so suppression must be file-level.
#![allow(clippy::ptr_as_ptr, clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::ptr::NonNull;

use pyo3::Borrowed;
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PySet, PyString, PyTuple, PyType};

use crate::common::config::{DEFAULT_RESERVE_FRACTION, MAX_FUNNEL_RESERVE_FRACTION};
use crate::{ElasticHashMap, FunnelHashMap};

fn validate_elastic_reserve_fraction(reserve_fraction: Option<f64>) -> PyResult<f64> {
    let Some(rf) = reserve_fraction else {
        return Ok(DEFAULT_RESERVE_FRACTION);
    };
    if !(rf > 0.0 && rf < 1.0) {
        return Err(PyValueError::new_err(
            "reserve_fraction must be in the open interval (0, 1)",
        ));
    }
    Ok(rf)
}

fn validate_funnel_reserve_fraction(reserve_fraction: Option<f64>) -> PyResult<f64> {
    let Some(rf) = reserve_fraction else {
        return Ok(DEFAULT_RESERVE_FRACTION);
    };
    if !(rf > 0.0 && rf <= MAX_FUNNEL_RESERVE_FRACTION) {
        return Err(PyValueError::new_err(format!(
            "reserve_fraction must be in (0, {MAX_FUNNEL_RESERVE_FRACTION}]; \
             FunnelHashMap caps the load factor at 1/8 by design"
        )));
    }
    Ok(rf)
}

/// Type tag packed into `HashedAny::tagged`'s low bits so `PartialEq` skips
/// `Py_TYPE` re-dispatch for str/str and int/int compares.
#[derive(Debug, PartialEq, Eq)]
#[repr(usize)]
enum HashKind {
    Other = 0,
    Str = 1,
    Int = 2,
}

/// Tag mask packing a [`HashKind`] into a `PyObject*` pointer. `CPython`
/// aligns object headers to at least 8 bytes, so the low 3 bits are
/// reliably zero — we use 2 of them.
const KIND_MASK: usize = 0b11;

/// Owning hashable wrapper for a `Py<PyAny>` map key. Caches `__hash__`
/// and tag-packs `HashKind` into the pointer's low bit; 16B on 64-bit.
struct HashedAny {
    /// `PyObject*` OR'd with `HashKind`. `Drop` calls `Py_DECREF` on the masked pointer.
    tagged: NonNull<ffi::PyObject>,
    /// Cached `__hash__` result.
    hash: isize,
}

// SAFETY: matches `Py<PyAny>` — atomic refcount, derefs only under `Python::attach`.
unsafe impl Send for HashedAny {}
unsafe impl Sync for HashedAny {}

const _: () = assert!(std::mem::size_of::<HashedAny>() == 2 * std::mem::size_of::<usize>());

impl HashedAny {
    /// Tag-pack `obj` with `kind`. No refcount change. Panics on null `obj` or
    /// non-zero `KIND_MASK` bits — both guaranteed by `CPython` for any
    /// `PyObject*` sourced from a live `Bound::as_ptr()`.
    #[inline]
    fn pack(obj: *mut ffi::PyObject, kind: HashKind) -> NonNull<ffi::PyObject> {
        assert!(!obj.is_null(), "PyObject pointer must be non-null");
        // Runtime (not debug) assert: silent pointer corruption is worse than
        // one extra cmp+jne in this cold path.
        assert_eq!(
            obj as usize & KIND_MASK,
            0,
            "PyObject* low bits must be zero for tag packing"
        );
        // `obj` non-null (asserted above) + ORing tag bits keeps it non-null.
        NonNull::new(((obj as usize) | (kind as usize)) as *mut ffi::PyObject)
            .expect("tagged PyObject* non-null")
    }

    #[inline]
    fn detect_kind(ob: &Bound<'_, PyAny>) -> HashKind {
        // SAFETY: `Bound` always holds a valid `PyObject*`.
        unsafe {
            let ty = ffi::Py_TYPE(ob.as_ptr());
            if ty == &raw mut ffi::PyUnicode_Type {
                HashKind::Str
            } else if ty == &raw mut ffi::PyLong_Type {
                HashKind::Int
            } else {
                HashKind::Other
            }
        }
    }

    /// Compute `__hash__` once and bump the object's refcount. Uses raw
    /// `Py_INCREF` rather than `Bound::clone().unbind() + forget` to avoid
    /// `Py<PyAny>` moves the optimizer doesn't always elide.
    fn from_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self> {
        let hash = ob.hash()?;
        let kind = Self::detect_kind(ob);
        let raw = ob.as_ptr();
        // SAFETY: `Bound` guarantees `raw` is non-null and the GIL is held.
        unsafe { ffi::Py_INCREF(raw) };
        let tagged = Self::pack(raw, kind);
        Ok(Self { tagged, hash })
    }

    /// Refcount-bumping clone. Reuses cached hash and tag.
    fn clone_with_py(&self, _py: Python<'_>) -> Self {
        // SAFETY: we hold a strong ref to `obj_ptr()`; GIL held.
        unsafe { ffi::Py_INCREF(self.obj_ptr()) };
        Self {
            tagged: self.tagged,
            hash: self.hash,
        }
    }

    /// Object pointer with tag bits stripped.
    #[inline]
    fn obj_ptr(&self) -> *mut ffi::PyObject {
        ((self.tagged.as_ptr() as usize) & !KIND_MASK) as *mut ffi::PyObject
    }

    /// Decoded `HashKind`. Exhaustive arms (not catch-all) so a new variant
    /// can't silently alias `Other`.
    #[inline]
    fn kind(&self) -> HashKind {
        match (self.tagged.as_ptr() as usize) & KIND_MASK {
            x if x == HashKind::Other as usize => HashKind::Other,
            x if x == HashKind::Str as usize => HashKind::Str,
            x if x == HashKind::Int as usize => HashKind::Int,
            // SAFETY: `KIND_MASK == 0b11` and every `HashKind` discriminant
            // in [0, 3] has an arm above. A new variant overlapping the
            // mask must add an arm here.
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// Borrowed handle (no refcount bump).
    #[inline]
    fn obj_borrowed<'a, 'py>(&'a self, py: Python<'py>) -> Borrowed<'a, 'py, PyAny> {
        // SAFETY: we own a strong ref; `'a` keeps it live.
        unsafe { Borrowed::from_ptr(py, self.obj_ptr()) }
    }

    /// Fresh owned `Py<PyAny>` (bumps refcount).
    #[inline]
    fn obj_clone_ref(&self, py: Python<'_>) -> Py<PyAny> {
        // SAFETY: we own a strong ref; `to_owned()` bumps it.
        unsafe { Borrowed::from_ptr(py, self.obj_ptr()) }
            .to_owned()
            .unbind()
    }
}

impl Drop for HashedAny {
    fn drop(&mut self) {
        // `Py_DECREF` needs the GIL — per-slot attach matches `Py<T>::drop`.
        Python::attach(|_py| {
            // SAFETY: we own one strong ref to the masked pointer.
            unsafe { ffi::Py_DECREF(self.obj_ptr()) };
        });
    }
}

/// Borrow-only key wrapper for non-owning lookups. Wraps a `HashedAny` in
/// `ManuallyDrop` so no refcount bump or `Py_DECREF` happens — the source
/// `Bound` keeps the object live.
struct ProbeKey {
    inner: ManuallyDrop<HashedAny>,
}

impl ProbeKey {
    /// Borrow `ob`'s `PyObject*` and cached hash without bumping refcount.
    ///
    /// # Safety
    /// `ob` must outlive the returned `ProbeKey`. The signature can't bind
    /// the probe's lifetime to `ob`, hence `unsafe fn`.
    unsafe fn from_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self> {
        let hash = ob.hash()?;
        let kind = HashedAny::detect_kind(ob);
        let tagged = HashedAny::pack(ob.as_ptr(), kind);
        Ok(Self {
            inner: ManuallyDrop::new(HashedAny { tagged, hash }),
        })
    }

    fn as_key(&self) -> &HashedAny {
        &self.inner
    }
}

impl Hash for HashedAny {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_isize(self.hash);
    }
}

impl PartialEq for HashedAny {
    /// Short-circuits before falling back to Python rich compare: hash
    /// mismatch, pointer identity, then a kind-tagged fast path —
    /// str/str via UTF-8 bytes and int/int via `PyLong_AsLongLongAndOverflow`.
    fn eq(&self, other: &Self) -> bool {
        if self.hash != other.hash {
            return false;
        }
        if self.obj_ptr() == other.obj_ptr() {
            return true;
        }
        let sk = self.kind();
        let ok = other.kind();
        Python::attach(|py| {
            // Direct UTF-8 compare bypasses PyObject_RichCompareBool dispatch.
            if sk == HashKind::Str
                && ok == HashKind::Str
                && let Ok(sa) = self.obj_borrowed(py).cast::<PyString>()
                && let Ok(sb) = other.obj_borrowed(py).cast::<PyString>()
                && let Ok(x) = sa.to_str()
                && let Ok(y) = sb.to_str()
            {
                return x == y;
            }
            // Int/int: try `c_longlong` direct compare; fall through to rich
            // compare only when both sides overflow in the same direction.
            if sk == HashKind::Int && ok == HashKind::Int {
                let mut ovf_a: std::ffi::c_int = 0;
                let mut ovf_b: std::ffi::c_int = 0;
                // SAFETY: kind tag guarantees both are PyLong.
                let a =
                    unsafe { ffi::PyLong_AsLongLongAndOverflow(self.obj_ptr(), &raw mut ovf_a) };
                let b =
                    unsafe { ffi::PyLong_AsLongLongAndOverflow(other.obj_ptr(), &raw mut ovf_b) };
                if ovf_a == 0 && ovf_b == 0 {
                    return a == b;
                }
                if ovf_a != ovf_b {
                    return false;
                }
            }
            self.obj_borrowed(py)
                .eq(other.obj_borrowed(py))
                .unwrap_or(false)
        })
    }
}

impl Eq for HashedAny {}

/// Emits one Python-facing map surface (class + iterators + views) per
/// backend. `PyO3` can't `#[pyclass]` over a generic, hence the macro;
/// invoked once each for `Elastic` and `Funnel` to keep behavior in sync.
macro_rules! define_map_classes {
    (
        py_map = $PyMap:ident,
        py_map_name = $py_map_name:literal,
        inner = $Inner:ident,
        validate_rf = $validate_rf:ident,
        key_iter = $KeyIter:ident,
        key_iter_name = $key_iter_name:literal,
        value_iter = $ValueIter:ident,
        value_iter_name = $value_iter_name:literal,
        item_iter = $ItemIter:ident,
        item_iter_name = $item_iter_name:literal,
        keys_view = $KeysView:ident,
        keys_view_name = $keys_view_name:literal,
        values_view = $ValuesView:ident,
        values_view_name = $values_view_name:literal,
        items_view = $ItemsView:ident,
        items_view_name = $items_view_name:literal,
    ) => {
        /// `PyO3` wrapper around the Rust hash map.
        #[pyclass(name = $py_map_name, module = "opthash")]
        struct $PyMap {
            inner: $Inner<HashedAny, Py<PyAny>>,
            /// Mutation counter snapshotted by iterators; mismatch on
            /// `__next__` raises `RuntimeError`.
            generation: u64,
        }

        impl $PyMap {
            /// Invalidate active iterator snapshots. Call after every mutation.
            #[inline]
            fn bump(&mut self) {
                self.generation = self.generation.wrapping_add(1);
            }
        }

        #[pymethods]
        impl $PyMap {
            #[new]
            #[pyo3(signature = (other = None, *, capacity = 0, **kwargs))]
            fn new(
                other: Option<&Bound<'_, PyAny>>,
                capacity: usize,
                kwargs: Option<&Bound<'_, PyDict>>,
            ) -> PyResult<Self> {
                let mut me = Self {
                    inner: $Inner::with_capacity(capacity),
                    generation: 0,
                };
                if other.is_some() || kwargs.is_some() {
                    me.update(other, kwargs)?;
                }
                Ok(me)
            }

            #[classmethod]
            #[pyo3(signature = (capacity = 0, reserve_fraction = None))]
            fn with_options(
                _cls: &Bound<'_, PyType>,
                capacity: usize,
                reserve_fraction: Option<f64>,
            ) -> PyResult<Self> {
                let rf = $validate_rf(reserve_fraction)?;
                Ok(Self {
                    inner: $Inner::with_capacity_and_reserve_fraction(capacity, rf),
                    generation: 0,
                })
            }

            #[classmethod]
            #[pyo3(signature = (iterable, value = None))]
            fn fromkeys(
                _cls: &Bound<'_, PyType>,
                iterable: &Bound<'_, PyAny>,
                value: Option<Py<PyAny>>,
                py: Python<'_>,
            ) -> PyResult<Self> {
                let cap = iterable.len().unwrap_or(0);
                let mut me = Self {
                    inner: $Inner::with_capacity(cap),
                    generation: 0,
                };
                let val = value.unwrap_or_else(|| py.None());
                for k in iterable.try_iter()? {
                    let k = k?;
                    let key = HashedAny::from_bound(&k)?;
                    me.inner.insert(key, val.clone_ref(py));
                }
                me.bump();
                Ok(me)
            }

            /// Runtime support for `Cls[K, V]` syntax via `types.GenericAlias`
            /// — parity with the `Generic[K, V]` typing stub.
            #[classmethod]
            fn __class_getitem__<'py>(
                cls: &Bound<'py, PyType>,
                item: &Bound<'py, PyAny>,
                py: Python<'py>,
            ) -> PyResult<Bound<'py, PyAny>> {
                py.import("types")?
                    .getattr("GenericAlias")?
                    .call1((cls, item))
            }

            fn __len__(&self) -> usize {
                self.inner.len()
            }

            #[getter]
            fn capacity(&self) -> usize {
                self.inner.capacity()
            }

            fn __contains__(&self, key: &Bound<'_, PyAny>) -> PyResult<bool> {
                // SAFETY: `key` lives for the whole function and outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                Ok(self.inner.contains_key(probe.as_key()))
            }

            fn __getitem__(&self, key: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PyAny>> {
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                match self.inner.get(probe.as_key()) {
                    Some(v) => Ok(v.clone_ref(py)),
                    None => Err(PyKeyError::new_err(key.clone().unbind())),
                }
            }

            fn __setitem__(
                &mut self,
                key: &Bound<'_, PyAny>,
                value: &Bound<'_, PyAny>,
            ) -> PyResult<()> {
                let k = HashedAny::from_bound(key)?;
                self.inner.insert(k, value.clone().unbind());
                self.bump();
                Ok(())
            }

            fn __delitem__(&mut self, key: &Bound<'_, PyAny>) -> PyResult<()> {
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                match self.inner.remove(probe.as_key()) {
                    Some(_) => {
                        self.bump();
                        Ok(())
                    }
                    None => Err(PyKeyError::new_err(key.clone().unbind())),
                }
            }

            #[pyo3(signature = (key, default = None))]
            fn get(
                &self,
                key: &Bound<'_, PyAny>,
                default: Option<Py<PyAny>>,
                py: Python<'_>,
            ) -> PyResult<Py<PyAny>> {
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                Ok(match self.inner.get(probe.as_key()) {
                    Some(v) => v.clone_ref(py),
                    None => default.unwrap_or_else(|| py.None()),
                })
            }

            fn clear(&mut self) {
                // One outer attach so per-entry `HashedAny::drop` hits the
                // cheap already-attached path instead of re-acquiring GIL state.
                Python::attach(|_py| self.inner.clear());
                self.bump();
            }

            fn __repr__(&self) -> String {
                format!(
                    concat!($py_map_name, "(len={}, capacity={})"),
                    self.inner.len(),
                    self.inner.capacity()
                )
            }

            fn __iter__(slf: Bound<'_, Self>) -> $KeyIter {
                let py = slf.py();
                let m = slf.borrow();
                let snapshot = m
                    .inner
                    .iter()
                    .map(|(k, _)| Some(k.obj_clone_ref(py)))
                    .collect();
                let expected_gen = m.generation;
                drop(m);
                $KeyIter {
                    map: slf.unbind(),
                    snapshot,
                    expected_gen,
                    pos: 0,
                }
            }

            fn keys(slf: Bound<'_, Self>) -> $KeysView {
                $KeysView { map: slf.unbind() }
            }

            fn values(slf: Bound<'_, Self>) -> $ValuesView {
                $ValuesView { map: slf.unbind() }
            }

            fn items(slf: Bound<'_, Self>) -> $ItemsView {
                $ItemsView { map: slf.unbind() }
            }

            /// Mirror of `dict.update`. Branches in priority order: same-type,
            /// `PyDict`, mapping with `keys()`, then `(k, v)` iterable. Reserves
            /// up front when length is known. `bump()` only on actual inserts —
            /// empty `update()` keeps iterators valid.
            #[pyo3(signature = (other = None, **kwargs))]
            fn update(
                &mut self,
                other: Option<&Bound<'_, PyAny>>,
                kwargs: Option<&Bound<'_, PyDict>>,
            ) -> PyResult<()> {
                let mut touched = false;
                if let Some(other) = other {
                    if let Ok(other_map) = other.cast::<Self>() {
                        let py = other.py();
                        let borrowed = other_map.borrow();
                        self.inner.reserve(borrowed.inner.len());
                        for (k, v) in &borrowed.inner {
                            self.inner.insert(k.clone_with_py(py), v.clone_ref(py));
                            touched = true;
                        }
                    } else if let Ok(dict) = other.cast::<PyDict>() {
                        self.inner.reserve(dict.len());
                        for (k, v) in dict.iter() {
                            let key = HashedAny::from_bound(&k)?;
                            self.inner.insert(key, v.unbind());
                            touched = true;
                        }
                    } else if other.hasattr("keys")? {
                        if let Ok(hint) = other.len() {
                            self.inner.reserve(hint);
                        }
                        let keys = other.call_method0("keys")?;
                        for k in keys.try_iter()? {
                            let k = k?;
                            let v = other.get_item(&k)?;
                            let key = HashedAny::from_bound(&k)?;
                            self.inner.insert(key, v.unbind());
                            touched = true;
                        }
                    } else {
                        if let Ok(hint) = other.len() {
                            self.inner.reserve(hint);
                        }
                        for item in other.try_iter()? {
                            let item = item?;
                            let len = item.len().map_err(|_| {
                                PyValueError::new_err("update sequence elements must be 2-tuples")
                            })?;
                            if len != 2 {
                                return Err(PyValueError::new_err(
                                    "update sequence elements must be 2-tuples",
                                ));
                            }
                            let k = item.get_item(0)?;
                            let v = item.get_item(1)?;
                            let key = HashedAny::from_bound(&k)?;
                            self.inner.insert(key, v.unbind());
                            touched = true;
                        }
                    }
                }
                if let Some(kwargs) = kwargs {
                    self.inner.reserve(kwargs.len());
                    for (k, v) in kwargs.iter() {
                        let key = HashedAny::from_bound(&k)?;
                        self.inner.insert(key, v.unbind());
                        touched = true;
                    }
                }
                if touched {
                    self.bump();
                }
                Ok(())
            }

            #[pyo3(signature = (key, default = None))]
            fn pop(
                &mut self,
                key: &Bound<'_, PyAny>,
                default: Option<Py<PyAny>>,
            ) -> PyResult<Py<PyAny>> {
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                match self.inner.remove(probe.as_key()) {
                    Some(v) => {
                        self.bump();
                        Ok(v)
                    }
                    None => default.ok_or_else(|| PyKeyError::new_err(key.clone().unbind())),
                }
            }

            fn popitem<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
                if self.inner.is_empty() {
                    return Err(PyKeyError::new_err("popitem(): map is empty"));
                }
                let (key_obj, value) = {
                    let (k, v) = self.inner.extract_if(|_, _| true).next().expect("len > 0");
                    (k.obj_clone_ref(py), v)
                };
                self.bump();
                PyTuple::new(py, [key_obj, value])
            }

            #[pyo3(signature = (key, default = None))]
            fn setdefault(
                &mut self,
                key: &Bound<'_, PyAny>,
                default: Option<Py<PyAny>>,
                py: Python<'_>,
            ) -> PyResult<Py<PyAny>> {
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                if let Some(v) = self.inner.get(probe.as_key()) {
                    return Ok(v.clone_ref(py));
                }
                let k = HashedAny::from_bound(key)?;
                let value = default.unwrap_or_else(|| py.None());
                self.inner.insert(k, value.clone_ref(py));
                self.bump();
                Ok(value)
            }

            fn copy(&self, py: Python<'_>) -> Self {
                let mut new = $Inner::with_capacity(self.inner.len());
                for (k, v) in &self.inner {
                    new.insert(k.clone_with_py(py), v.clone_ref(py));
                }
                Self {
                    inner: new,
                    generation: 0,
                }
            }

            fn __eq__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> bool {
                if let Ok(other_map) = other.cast::<Self>() {
                    let other_inner = &other_map.borrow().inner;
                    if self.inner.len() != other_inner.len() {
                        return false;
                    }
                    for (k, v) in &self.inner {
                        match other_inner.get(k) {
                            Some(ov) => {
                                if !v.bind(py).eq(ov.bind(py)).unwrap_or(false) {
                                    return false;
                                }
                            }
                            None => return false,
                        }
                    }
                    return true;
                }
                if let Ok(d) = other.cast::<PyDict>() {
                    if d.len() != self.inner.len() {
                        return false;
                    }
                    for (k, v) in &self.inner {
                        let key_b = k.obj_borrowed(py);
                        match d.get_item(key_b) {
                            Ok(Some(other_v)) => {
                                if !v.bind(py).eq(&other_v).unwrap_or(false) {
                                    return false;
                                }
                            }
                            _ => return false,
                        }
                    }
                    return true;
                }
                if !other.hasattr("keys").unwrap_or(false) {
                    return false;
                }
                let Ok(other_len) = other.len() else {
                    return false;
                };
                if other_len != self.inner.len() {
                    return false;
                }
                for (k, v) in &self.inner {
                    let key_b = k.obj_borrowed(py);
                    let Ok(other_v) = other.get_item(key_b) else {
                        return false;
                    };
                    if !v.bind(py).eq(&other_v).unwrap_or(false) {
                        return false;
                    }
                }
                true
            }

            fn __or__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Self> {
                let other_hint = other.len().unwrap_or(0);
                let cap = self.inner.len().saturating_add(other_hint);
                let mut new = Self {
                    inner: $Inner::with_capacity(cap),
                    generation: 0,
                };
                for (k, v) in &self.inner {
                    new.inner.insert(k.clone_with_py(py), v.clone_ref(py));
                }
                new.update(Some(other), None)?;
                Ok(new)
            }

            fn __ror__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Self> {
                let other_hint = other.len().unwrap_or(0);
                let cap = self.inner.len().saturating_add(other_hint);
                let mut new = Self {
                    inner: $Inner::with_capacity(cap),
                    generation: 0,
                };
                new.update(Some(other), None)?;
                for (k, v) in &self.inner {
                    new.inner.insert(k.clone_with_py(py), v.clone_ref(py));
                }
                new.bump();
                Ok(new)
            }

            fn __ior__(&mut self, other: &Bound<'_, PyAny>) -> PyResult<()> {
                self.update(Some(other), None)
            }
        }

        define_iter!($KeyIter, $key_iter_name, $PyMap);
        define_iter!($ValueIter, $value_iter_name, $PyMap);
        define_iter!($ItemIter, $item_iter_name, $PyMap);

        /// Live view over keys (mirrors `dict.keys()`). Holds `Py<map>` so
        /// each op sees current state — no snapshot at view construction.
        #[pyclass(name = $keys_view_name, module = "opthash")]
        struct $KeysView {
            map: Py<$PyMap>,
        }

        #[pymethods]
        impl $KeysView {
            fn __iter__(&self, py: Python<'_>) -> $KeyIter {
                let m = self.map.borrow(py);
                let snapshot = m
                    .inner
                    .iter()
                    .map(|(k, _)| Some(k.obj_clone_ref(py)))
                    .collect();
                $KeyIter {
                    map: self.map.clone_ref(py),
                    snapshot,
                    expected_gen: m.generation,
                    pos: 0,
                }
            }
            fn __len__(&self, py: Python<'_>) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, key: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<bool> {
                let m = self.map.borrow(py);
                // SAFETY: `key` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(key) }?;
                Ok(m.inner.contains_key(probe.as_key()))
            }
            fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
                let m = self.map.borrow(py);
                let parts: PyResult<Vec<String>> = m
                    .inner
                    .iter()
                    .map(|(k, _)| Ok(k.obj_borrowed(py).repr()?.to_string()))
                    .collect();
                Ok(format!(
                    concat!($keys_view_name, "([{}])"),
                    parts?.join(", ")
                ))
            }
            fn __eq__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> bool {
                let m = self.map.borrow(py);
                let Ok(other_len) = other.len() else {
                    return false;
                };
                if other_len != m.inner.len() {
                    return false;
                }
                for (k, _) in &m.inner {
                    if !other.contains(k.obj_borrowed(py)).unwrap_or(false) {
                        return false;
                    }
                }
                true
            }
            fn __and__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                let m = self.map.borrow(py);
                for (k, _) in &m.inner {
                    let key_b = k.obj_borrowed(py);
                    if other.contains(key_b)? {
                        result.add(key_b)?;
                    }
                }
                Ok(result.unbind())
            }
            fn __or__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                {
                    let m = self.map.borrow(py);
                    for (k, _) in &m.inner {
                        result.add(k.obj_borrowed(py))?;
                    }
                }
                for item in other.try_iter()? {
                    result.add(item?)?;
                }
                Ok(result.unbind())
            }
            fn __sub__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                let m = self.map.borrow(py);
                for (k, _) in &m.inner {
                    let key_b = k.obj_borrowed(py);
                    if !other.contains(key_b)? {
                        result.add(key_b)?;
                    }
                }
                Ok(result.unbind())
            }
            fn __xor__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                {
                    let m = self.map.borrow(py);
                    for (k, _) in &m.inner {
                        let key_b = k.obj_borrowed(py);
                        if !other.contains(key_b)? {
                            result.add(key_b)?;
                        }
                    }
                }
                let m = self.map.borrow(py);
                for item in other.try_iter()? {
                    let item = item?;
                    // SAFETY: `item` outlives `probe`; both go out of scope
                    // at the end of this loop iteration.
                    let probe = unsafe { ProbeKey::from_bound(&item) }?;
                    if !m.inner.contains_key(probe.as_key()) {
                        result.add(item)?;
                    }
                }
                Ok(result.unbind())
            }
        }

        /// Live view over values (mirrors `dict.values()`).
        #[pyclass(name = $values_view_name, module = "opthash")]
        struct $ValuesView {
            map: Py<$PyMap>,
        }

        #[pymethods]
        impl $ValuesView {
            fn __iter__(&self, py: Python<'_>) -> $ValueIter {
                let m = self.map.borrow(py);
                let snapshot = m.inner.iter().map(|(_, v)| Some(v.clone_ref(py))).collect();
                $ValueIter {
                    map: self.map.clone_ref(py),
                    snapshot,
                    expected_gen: m.generation,
                    pos: 0,
                }
            }
            fn __len__(&self, py: Python<'_>) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, value: &Bound<'_, PyAny>, py: Python<'_>) -> bool {
                let m = self.map.borrow(py);
                for (_, v) in &m.inner {
                    if v.bind(py).eq(value).unwrap_or(false) {
                        return true;
                    }
                }
                false
            }
            fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
                let m = self.map.borrow(py);
                let parts: PyResult<Vec<String>> = m
                    .inner
                    .iter()
                    .map(|(_, v)| Ok(v.bind(py).repr()?.to_string()))
                    .collect();
                Ok(format!(
                    concat!($values_view_name, "([{}])"),
                    parts?.join(", ")
                ))
            }
        }

        /// Live view over `(key, value)` pairs (mirrors `dict.items()`).
        /// Set ops build fresh `(k, v)` `PyTuple`s.
        #[pyclass(name = $items_view_name, module = "opthash")]
        struct $ItemsView {
            map: Py<$PyMap>,
        }

        #[pymethods]
        impl $ItemsView {
            fn __iter__(&self, py: Python<'_>) -> PyResult<$ItemIter> {
                let m = self.map.borrow(py);
                let snapshot: PyResult<Vec<Option<Py<PyAny>>>> = m
                    .inner
                    .iter()
                    .map(|(k, v)| {
                        let tup = PyTuple::new(py, [k.obj_clone_ref(py), v.clone_ref(py)])?;
                        Ok(Some(tup.into_any().unbind()))
                    })
                    .collect();
                Ok($ItemIter {
                    map: self.map.clone_ref(py),
                    snapshot: snapshot?,
                    expected_gen: m.generation,
                    pos: 0,
                })
            }
            fn __len__(&self, py: Python<'_>) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, item: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<bool> {
                let Ok(tup) = item.cast::<PyTuple>() else {
                    return Ok(false);
                };
                if tup.len() != 2 {
                    return Ok(false);
                }
                let k = tup.get_item(0)?;
                let v = tup.get_item(1)?;
                let m = self.map.borrow(py);
                // SAFETY: `k` outlives `probe`.
                let probe = unsafe { ProbeKey::from_bound(&k) }?;
                match m.inner.get(probe.as_key()) {
                    Some(stored_v) => Ok(stored_v.bind(py).eq(&v).unwrap_or(false)),
                    None => Ok(false),
                }
            }
            fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
                let m = self.map.borrow(py);
                let parts: PyResult<Vec<String>> = m
                    .inner
                    .iter()
                    .map(|(k, v)| {
                        let kr = k.obj_borrowed(py).repr()?.to_string();
                        let vr = v.bind(py).repr()?.to_string();
                        Ok(format!("({kr}, {vr})"))
                    })
                    .collect();
                Ok(format!(
                    concat!($items_view_name, "([{}])"),
                    parts?.join(", ")
                ))
            }
            fn __eq__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> bool {
                let m = self.map.borrow(py);
                let Ok(other_len) = other.len() else {
                    return false;
                };
                if other_len != m.inner.len() {
                    return false;
                }
                for (k, v) in &m.inner {
                    let Ok(tup) = PyTuple::new(py, [k.obj_clone_ref(py), v.clone_ref(py)]) else {
                        return false;
                    };
                    if !other.contains(&tup).unwrap_or(false) {
                        return false;
                    }
                }
                true
            }
            fn __and__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                let m = self.map.borrow(py);
                for (k, v) in &m.inner {
                    let tup = PyTuple::new(py, [k.obj_clone_ref(py), v.clone_ref(py)])?;
                    if other.contains(&tup)? {
                        result.add(tup)?;
                    }
                }
                Ok(result.unbind())
            }
            fn __or__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                {
                    let m = self.map.borrow(py);
                    for (k, v) in &m.inner {
                        let tup = PyTuple::new(py, [k.obj_clone_ref(py), v.clone_ref(py)])?;
                        result.add(tup)?;
                    }
                }
                for item in other.try_iter()? {
                    result.add(item?)?;
                }
                Ok(result.unbind())
            }
            fn __sub__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<Py<PySet>> {
                let result = PySet::empty(py)?;
                let m = self.map.borrow(py);
                for (k, v) in &m.inner {
                    let tup = PyTuple::new(py, [k.obj_clone_ref(py), v.clone_ref(py)])?;
                    if !other.contains(&tup)? {
                        result.add(tup)?;
                    }
                }
                Ok(result.unbind())
            }
        }
    };
}

/// One iterator pyclass. `snapshot` is materialized eagerly at `__iter__`
/// (trades memory for no self-referencing borrow). `__next__` checks
/// `expected_gen` against the map's `generation` and raises on mismatch.
///
/// Slot type is `Option<Py<PyAny>>` (niche-packed, same size as `Py`); each
/// `__next__` `.take()`s the slot rather than cloning — saves one atomic
/// refcount bump per yield.
macro_rules! define_iter {
    ($Iter:ident, $iter_name:literal, $PyMap:ident) => {
        #[pyclass(name = $iter_name, module = "opthash")]
        struct $Iter {
            map: Py<$PyMap>,
            snapshot: Vec<Option<Py<PyAny>>>,
            expected_gen: u64,
            pos: usize,
        }

        #[pymethods]
        impl $Iter {
            fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
                slf
            }
            fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
                if self.map.borrow(py).generation != self.expected_gen {
                    return Err(PyRuntimeError::new_err(
                        "dictionary changed size during iteration",
                    ));
                }
                let Some(slot) = self.snapshot.get_mut(self.pos) else {
                    return Ok(None);
                };
                self.pos += 1;
                Ok(slot.take())
            }
        }
    };
}

define_map_classes! {
    py_map = PyElasticHashMap,
    py_map_name = "ElasticHashMap",
    inner = ElasticHashMap,
    validate_rf = validate_elastic_reserve_fraction,
    key_iter = PyElasticKeyIter,
    key_iter_name = "_ElasticKeyIter",
    value_iter = PyElasticValueIter,
    value_iter_name = "_ElasticValueIter",
    item_iter = PyElasticItemIter,
    item_iter_name = "_ElasticItemIter",
    keys_view = PyElasticKeysView,
    keys_view_name = "elastic_keys",
    values_view = PyElasticValuesView,
    values_view_name = "elastic_values",
    items_view = PyElasticItemsView,
    items_view_name = "elastic_items",
}

define_map_classes! {
    py_map = PyFunnelHashMap,
    py_map_name = "FunnelHashMap",
    inner = FunnelHashMap,
    validate_rf = validate_funnel_reserve_fraction,
    key_iter = PyFunnelKeyIter,
    key_iter_name = "_FunnelKeyIter",
    value_iter = PyFunnelValueIter,
    value_iter_name = "_FunnelValueIter",
    item_iter = PyFunnelItemIter,
    item_iter_name = "_FunnelItemIter",
    keys_view = PyFunnelKeysView,
    keys_view_name = "funnel_keys",
    values_view = PyFunnelValuesView,
    values_view_name = "funnel_values",
    items_view = PyFunnelItemsView,
    items_view_name = "funnel_items",
}

#[pymodule]
fn opthash(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyElasticHashMap>()?;
    m.add_class::<PyFunnelHashMap>()?;
    m.add_class::<PyElasticKeysView>()?;
    m.add_class::<PyElasticValuesView>()?;
    m.add_class::<PyElasticItemsView>()?;
    m.add_class::<PyElasticKeyIter>()?;
    m.add_class::<PyElasticValueIter>()?;
    m.add_class::<PyElasticItemIter>()?;
    m.add_class::<PyFunnelKeysView>()?;
    m.add_class::<PyFunnelValuesView>()?;
    m.add_class::<PyFunnelItemsView>()?;
    m.add_class::<PyFunnelKeyIter>()?;
    m.add_class::<PyFunnelValueIter>()?;
    m.add_class::<PyFunnelItemIter>()?;
    Ok(())
}
