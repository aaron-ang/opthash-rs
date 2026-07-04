#![cfg(feature = "python")]
// Raw-pointer casts in pyo3 macro expansions. Per-fn `#[allow]` doesn't reach
// the generated wrapper, so suppression must be file-level.
#![allow(clippy::ptr_as_ptr, clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ptr::NonNull;

use pyo3::Borrowed;
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyFrozenSet, PySet, PyString, PyTuple, PyType};

use crate::common::config::DEFAULT_RESERVE_FRACTION;
use crate::funnel::MAX_FUNNEL_RESERVE_FRACTION;
use crate::map::{HashMap, TableProbing};
use crate::set::HashSet;
use crate::{ElasticHashMap, ElasticHashSet, FunnelHashMap, FunnelHashSet};

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

fn missing_key(key: &Bound<PyAny>) -> PyErr {
    PyKeyError::new_err(key.clone().unbind())
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
    fn detect_kind(ob: &Bound<PyAny>) -> HashKind {
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
    fn from_bound(ob: &Bound<PyAny>) -> PyResult<Self> {
        let hash = ob.hash()?;
        let kind = Self::detect_kind(ob);
        let raw = ob.as_ptr();
        // SAFETY: `Bound` guarantees `raw` is non-null and the GIL is held.
        unsafe { ffi::Py_INCREF(raw) };
        let tagged = Self::pack(raw, kind);
        Ok(Self { tagged, hash })
    }

    /// Refcount-bumping clone. Reuses cached hash and tag.
    fn clone_with_py(&self, _py: Python) -> Self {
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
    fn obj_clone_ref(&self, py: Python) -> Py<PyAny> {
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
/// `ManuallyDrop` so no refcount bump or `Py_DECREF` happens; the `'a` borrow
/// of the source `Bound` keeps the object live for the probe's lifetime.
struct ProbeKey<'a> {
    inner: ManuallyDrop<HashedAny>,
    _borrow: PhantomData<&'a PyAny>,
}

impl<'a> ProbeKey<'a> {
    /// Borrow `ob`'s `PyObject*` and cached hash without bumping refcount.
    /// The probe borrows `ob`, so the borrow checker keeps it from outliving
    /// the live object — no `unsafe` at the call site.
    fn from_bound(ob: &'a Bound<PyAny>) -> PyResult<Self> {
        let hash = ob.hash()?;
        let kind = HashedAny::detect_kind(ob);
        let tagged = HashedAny::pack(ob.as_ptr(), kind);
        Ok(Self {
            inner: ManuallyDrop::new(HashedAny { tagged, hash }),
            _borrow: PhantomData,
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

// ---------------------------------------------------------------------------
// Backend-generic map operations. The per-backend `#[pyclass]` shims below
// resolve the same-type fast path (`other.cast::<Self>()`) and pass the peer's
// `inner` as `same_inner`; all the actual logic lives here, once, reachable by
// rust-analyzer, unit tests, and coverage. `P` is the backend table; every op
// works on the generic [`HashMap`] shell.
// ---------------------------------------------------------------------------

/// Clone every entry of `src` into `dst` under `py`.
fn map_extend_cloned<P: TableProbing<HashedAny, Py<PyAny>>>(
    dst: &mut HashMap<HashedAny, Py<PyAny>, P>,
    src: &HashMap<HashedAny, Py<PyAny>, P>,
    py: Python,
) {
    for (k, v) in src {
        dst.insert(k.clone_with_py(py), v.clone_ref(py));
    }
}

/// Apply `dict.update` semantics to `inner`: same-type peer (`same_inner`,
/// honored regardless of `other`), then `PyDict`, `keys()` mapping, `(k, v)`
/// iterable, and `kwargs`. Return whether anything was inserted (the caller
/// bumps its generation only on a real change).
fn map_update<P: TableProbing<HashedAny, Py<PyAny>>>(
    inner: &mut HashMap<HashedAny, Py<PyAny>, P>,
    other: Option<&Bound<PyAny>>,
    kwargs: Option<&Bound<PyDict>>,
    py: Python,
    same_inner: Option<&HashMap<HashedAny, Py<PyAny>, P>>,
) -> PyResult<bool> {
    let mut touched = false;
    if let Some(peer) = same_inner {
        inner.reserve(peer.len());
        for (k, v) in peer {
            inner.insert(k.clone_with_py(py), v.clone_ref(py));
            touched = true;
        }
    } else if let Some(other) = other {
        if let Ok(dict) = other.cast::<PyDict>() {
            inner.reserve(dict.len());
            for (k, v) in dict.iter() {
                let key = HashedAny::from_bound(&k)?;
                inner.insert(key, v.unbind());
                touched = true;
            }
        } else if other.hasattr("keys")? {
            if let Ok(hint) = other.len() {
                inner.reserve(hint);
            }
            let keys = other.call_method0("keys")?;
            for k in keys.try_iter()? {
                let k = k?;
                let v = other.get_item(&k)?;
                let key = HashedAny::from_bound(&k)?;
                inner.insert(key, v.unbind());
                touched = true;
            }
        } else {
            if let Ok(hint) = other.len() {
                inner.reserve(hint);
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
                inner.insert(key, v.unbind());
                touched = true;
            }
        }
    }
    if let Some(kwargs) = kwargs {
        inner.reserve(kwargs.len());
        for (k, v) in kwargs.iter() {
            let key = HashedAny::from_bound(&k)?;
            inner.insert(key, v.unbind());
            touched = true;
        }
    }
    Ok(touched)
}

/// Compare `inner` to `other` (same-type, `PyDict`, or any `keys()` mapping)
/// by key membership and per-value Python `==`.
fn map_eq<P: TableProbing<HashedAny, Py<PyAny>>>(
    inner: &HashMap<HashedAny, Py<PyAny>, P>,
    other: &Bound<PyAny>,
    py: Python,
    same_inner: Option<&HashMap<HashedAny, Py<PyAny>, P>>,
) -> bool {
    if let Some(peer) = same_inner {
        if inner.len() != peer.len() {
            return false;
        }
        for (k, v) in inner {
            match peer.get(k) {
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
        if d.len() != inner.len() {
            return false;
        }
        for (k, v) in inner {
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
    if other_len != inner.len() {
        return false;
    }
    for (k, v) in inner {
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

/// Route a `#[pyclass]` method to its backend-generic op, resolving the
/// same-type fast path: if `other` is the same pyclass, borrow its `inner` and
/// pass it as the trailing `same_inner`, else pass `None`. `$recv` is
/// `&self.inner` or `&mut self.inner`; `$arg`s go between `other` and `same_inner`.
macro_rules! dispatch_same_type {
    ($f:ident, $recv:expr, $other:expr $(, $arg:expr)*) => {
        match $other.cast::<Self>() {
            Ok(o) => {
                let peer = o.borrow();
                $f($recv, $other $(, $arg)*, Some(&peer.inner))
            }
            Err(_) => $f($recv, $other $(, $arg)*, None),
        }
    };
}

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

            #[inline]
            fn bump_if_changed(&mut self, changed: bool) {
                if changed {
                    self.bump();
                }
            }
        }

        #[pymethods]
        impl $PyMap {
            #[new]
            #[pyo3(signature = (other = None, *, capacity = 0, **kwargs))]
            fn new(
                other: Option<&Bound<PyAny>>,
                capacity: usize,
                kwargs: Option<&Bound<PyDict>>,
                py: Python,
            ) -> PyResult<Self> {
                let mut me = Self {
                    inner: $Inner::with_capacity(capacity),
                    generation: 0,
                };
                if other.is_some() || kwargs.is_some() {
                    me.update(other, kwargs, py)?;
                }
                Ok(me)
            }

            #[classmethod]
            #[pyo3(signature = (capacity = 0, reserve_fraction = None))]
            fn with_options(
                _cls: &Bound<PyType>,
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
                _cls: &Bound<PyType>,
                iterable: &Bound<PyAny>,
                value: Option<Py<PyAny>>,
                py: Python,
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

            fn __contains__(&self, key: &Bound<PyAny>) -> PyResult<bool> {
                let probe = ProbeKey::from_bound(key)?;
                Ok(self.inner.contains_key(probe.as_key()))
            }

            fn __getitem__(&self, key: &Bound<PyAny>, py: Python) -> PyResult<Py<PyAny>> {
                let probe = ProbeKey::from_bound(key)?;
                match self.inner.get(probe.as_key()) {
                    Some(v) => Ok(v.clone_ref(py)),
                    None => Err(missing_key(key)),
                }
            }

            fn __setitem__(&mut self, key: &Bound<PyAny>, value: &Bound<PyAny>) -> PyResult<()> {
                let k = HashedAny::from_bound(key)?;
                self.inner.insert(k, value.clone().unbind());
                self.bump();
                Ok(())
            }

            fn __delitem__(&mut self, key: &Bound<PyAny>) -> PyResult<()> {
                let probe = ProbeKey::from_bound(key)?;
                match self.inner.remove(probe.as_key()) {
                    Some(_) => {
                        self.bump();
                        Ok(())
                    }
                    None => Err(missing_key(key)),
                }
            }

            #[pyo3(signature = (key, default = None))]
            fn get(
                &self,
                key: &Bound<PyAny>,
                default: Option<Py<PyAny>>,
                py: Python,
            ) -> PyResult<Py<PyAny>> {
                let probe = ProbeKey::from_bound(key)?;
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

            fn __iter__(slf: Bound<Self>) -> $KeyIter {
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

            fn keys(slf: Bound<Self>) -> $KeysView {
                $KeysView { map: slf.unbind() }
            }

            fn values(slf: Bound<Self>) -> $ValuesView {
                $ValuesView { map: slf.unbind() }
            }

            fn items(slf: Bound<Self>) -> $ItemsView {
                $ItemsView { map: slf.unbind() }
            }

            /// Mirror of `dict.update`; see [`map_update`] for the branch logic.
            /// `bump()` only on actual inserts — empty `update()` keeps
            /// iterators valid.
            #[pyo3(signature = (other = None, **kwargs))]
            fn update(
                &mut self,
                other: Option<&Bound<PyAny>>,
                kwargs: Option<&Bound<PyDict>>,
                py: Python,
            ) -> PyResult<()> {
                let touched = match other.and_then(|o| o.cast::<Self>().ok()) {
                    Some(o) => {
                        let peer = o.borrow();
                        map_update(&mut self.inner, other, kwargs, py, Some(&peer.inner))?
                    }
                    None => map_update(&mut self.inner, other, kwargs, py, None)?,
                };
                self.bump_if_changed(touched);
                Ok(())
            }

            #[pyo3(signature = (key, default = None))]
            fn pop(
                &mut self,
                key: &Bound<PyAny>,
                default: Option<Py<PyAny>>,
            ) -> PyResult<Py<PyAny>> {
                let probe = ProbeKey::from_bound(key)?;
                match self.inner.remove(probe.as_key()) {
                    Some(v) => {
                        self.bump();
                        Ok(v)
                    }
                    None => default.ok_or_else(|| missing_key(key)),
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
                key: &Bound<PyAny>,
                default: Option<Py<PyAny>>,
                py: Python,
            ) -> PyResult<Py<PyAny>> {
                let probe = ProbeKey::from_bound(key)?;
                if let Some(v) = self.inner.get(probe.as_key()) {
                    return Ok(v.clone_ref(py));
                }
                let k = HashedAny::from_bound(key)?;
                let value = default.unwrap_or_else(|| py.None());
                self.inner.insert(k, value.clone_ref(py));
                self.bump();
                Ok(value)
            }

            fn copy(&self, py: Python) -> Self {
                let mut new = $Inner::with_capacity(self.inner.len());
                map_extend_cloned(&mut new, &self.inner, py);
                Self {
                    inner: new,
                    generation: 0,
                }
            }

            fn __eq__(&self, other: &Bound<PyAny>, py: Python) -> bool {
                dispatch_same_type!(map_eq, &self.inner, other, py)
            }

            fn __or__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let other_hint = other.len().unwrap_or(0);
                let cap = self.inner.len().saturating_add(other_hint);
                let mut new = Self {
                    inner: $Inner::with_capacity(cap),
                    generation: 0,
                };
                map_extend_cloned(&mut new.inner, &self.inner, py);
                new.update(Some(other), None, py)?;
                Ok(new)
            }

            fn __ror__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let other_hint = other.len().unwrap_or(0);
                let cap = self.inner.len().saturating_add(other_hint);
                let mut new = Self {
                    inner: $Inner::with_capacity(cap),
                    generation: 0,
                };
                new.update(Some(other), None, py)?;
                map_extend_cloned(&mut new.inner, &self.inner, py);
                new.bump();
                Ok(new)
            }

            fn __ior__(&mut self, other: &Bound<PyAny>, py: Python) -> PyResult<()> {
                self.update(Some(other), None, py)
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
            fn __iter__(&self, py: Python) -> $KeyIter {
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
            fn __len__(&self, py: Python) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, key: &Bound<PyAny>, py: Python) -> PyResult<bool> {
                let m = self.map.borrow(py);
                let probe = ProbeKey::from_bound(key)?;
                Ok(m.inner.contains_key(probe.as_key()))
            }
            fn __repr__(&self, py: Python) -> PyResult<String> {
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
            fn __eq__(&self, other: &Bound<PyAny>, py: Python) -> bool {
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
            fn __and__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __or__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __sub__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __xor__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
                    let probe = ProbeKey::from_bound(&item)?;
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
            fn __iter__(&self, py: Python) -> $ValueIter {
                let m = self.map.borrow(py);
                let snapshot = m.inner.iter().map(|(_, v)| Some(v.clone_ref(py))).collect();
                $ValueIter {
                    map: self.map.clone_ref(py),
                    snapshot,
                    expected_gen: m.generation,
                    pos: 0,
                }
            }
            fn __len__(&self, py: Python) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, value: &Bound<PyAny>, py: Python) -> bool {
                let m = self.map.borrow(py);
                for (_, v) in &m.inner {
                    if v.bind(py).eq(value).unwrap_or(false) {
                        return true;
                    }
                }
                false
            }
            fn __repr__(&self, py: Python) -> PyResult<String> {
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
            fn __iter__(&self, py: Python) -> PyResult<$ItemIter> {
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
            fn __len__(&self, py: Python) -> usize {
                self.map.borrow(py).inner.len()
            }
            fn __contains__(&self, item: &Bound<PyAny>, py: Python) -> PyResult<bool> {
                let Ok(tup) = item.cast::<PyTuple>() else {
                    return Ok(false);
                };
                if tup.len() != 2 {
                    return Ok(false);
                }
                let k = tup.get_item(0)?;
                let v = tup.get_item(1)?;
                let m = self.map.borrow(py);
                let probe = ProbeKey::from_bound(&k)?;
                match m.inner.get(probe.as_key()) {
                    Some(stored_v) => Ok(stored_v.bind(py).eq(&v).unwrap_or(false)),
                    None => Ok(false),
                }
            }
            fn __repr__(&self, py: Python) -> PyResult<String> {
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
            fn __eq__(&self, other: &Bound<PyAny>, py: Python) -> bool {
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
            fn __and__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __or__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __sub__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Py<PySet>> {
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
            fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
                slf
            }
            fn __next__(&mut self, py: Python) -> PyResult<Option<Py<PyAny>>> {
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

/// `true` if `other` is set-like (builtin `set`/`frozenset`, an opthash set,
/// or anything registered with `collections.abc.Set`). Used by `__eq__` so a
/// set never compares equal to a non-set (e.g. a list with the same elements).
fn is_set_like(other: &Bound<PyAny>) -> PyResult<bool> {
    if other.is_instance_of::<PySet>() || other.is_instance_of::<PyFrozenSet>() {
        return Ok(true);
    }
    let set_abc = other.py().import("collections.abc")?.getattr("Set")?;
    other.is_instance(&set_abc)
}

// ---------------------------------------------------------------------------
// Backend-generic set operations. The per-backend `#[pyclass]` shims below
// resolve the same-type fast path (`other.cast::<Self>()`) and pass the peer's
// `inner` as `same_inner`; all the actual logic lives here, once, reachable by
// rust-analyzer, unit tests, and coverage. `P` is the backend table; every op
// works on the generic [`HashSet`] shell.
// ---------------------------------------------------------------------------

/// Insert every element of `other` into `inner`; return whether it changed.
fn set_add_all<P: TableProbing<HashedAny, ()>>(
    inner: &mut HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    let before = inner.len();
    if let Some(peer) = same_inner {
        let py = other.py();
        inner.reserve(peer.len());
        for value in peer {
            inner.insert(value.clone_with_py(py));
        }
    } else {
        if let Ok(hint) = other.len() {
            inner.reserve(hint);
        }
        for item in other.try_iter()? {
            let item = item?;
            inner.insert(HashedAny::from_bound(&item)?);
        }
    }
    Ok(inner.len() != before)
}

/// Remove every element of `other` from `inner`; return whether it changed.
fn set_remove_all<P: TableProbing<HashedAny, ()>>(
    inner: &mut HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    let before = inner.len();
    if let Some(peer) = same_inner {
        for value in peer {
            inner.remove(value);
        }
    } else {
        for item in other.try_iter()? {
            let item = item?;
            let probe = ProbeKey::from_bound(&item)?;
            inner.remove(probe.as_key());
        }
    }
    Ok(inner.len() != before)
}

/// Retain only elements also in `other`; return whether it changed.
fn set_retain_in<P: TableProbing<HashedAny, ()>>(
    inner: &mut HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    py: Python,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    let before = inner.len();
    if let Some(peer) = same_inner {
        inner.retain(|value| peer.contains(value));
        return Ok(inner.len() != before);
    }
    let other_set = PySet::empty(py)?;
    for item in other.try_iter()? {
        other_set.add(item?)?;
    }
    inner.retain(|value| other_set.contains(value.obj_borrowed(py)).unwrap_or(false));
    Ok(inner.len() != before)
}

/// Symmetric-difference `inner` with `other` in place; return whether it
/// changed (any non-empty `other` counts as changed).
fn set_symmetric_difference_with<P: TableProbing<HashedAny, ()>>(
    inner: &mut HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    if let Some(peer) = same_inner {
        let py = other.py();
        let mut touched = false;
        for value in peer {
            if !inner.remove(value) {
                inner.insert(value.clone_with_py(py));
            }
            touched = true;
        }
        return Ok(touched);
    }
    let mut unique_other = std::collections::HashSet::new();
    for item in other.try_iter()? {
        let item = item?;
        unique_other.insert(HashedAny::from_bound(&item)?);
    }
    let mut touched = false;
    for value in unique_other {
        if !inner.remove(&value) {
            inner.insert(value);
        }
        touched = true;
    }
    Ok(touched)
}

/// Report whether `inner` and `other` share no elements.
fn set_isdisjoint<P: TableProbing<HashedAny, ()>>(
    inner: &HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    if let Some(peer) = same_inner {
        let (smaller, larger) = if inner.len() <= peer.len() {
            (inner, peer)
        } else {
            (peer, inner)
        };
        for value in smaller {
            if larger.contains(value) {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    for item in other.try_iter()? {
        let item = item?;
        let probe = ProbeKey::from_bound(&item)?;
        if inner.contains(probe.as_key()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Report whether every element of `inner` is in `other`.
fn set_issubset<P: TableProbing<HashedAny, ()>>(
    inner: &HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    py: Python,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    if let Some(peer) = same_inner {
        if inner.len() > peer.len() {
            return Ok(false);
        }
        for value in inner {
            if !peer.contains(value) {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let other_set = PySet::empty(py)?;
    for item in other.try_iter()? {
        other_set.add(item?)?;
    }
    // `inner` is a set, so it cannot be a subset of a smaller collection.
    if other_set.len() < inner.len() {
        return Ok(false);
    }
    for value in inner {
        if !other_set.contains(value.obj_borrowed(py))? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Report whether every element of `other` is in `inner`.
fn set_issuperset<P: TableProbing<HashedAny, ()>>(
    inner: &HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    if let Some(peer) = same_inner {
        if inner.len() < peer.len() {
            return Ok(false);
        }
        for value in peer {
            if !inner.contains(value) {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    for item in other.try_iter()? {
        let item = item?;
        let probe = ProbeKey::from_bound(&item)?;
        if !inner.contains(probe.as_key()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Report whether `inner` equals `other` (same length and membership); a
/// non-set-like `other` is unequal.
fn set_eq<P: TableProbing<HashedAny, ()>>(
    inner: &HashSet<HashedAny, P>,
    other: &Bound<PyAny>,
    same_inner: Option<&HashSet<HashedAny, P>>,
) -> PyResult<bool> {
    if let Some(peer) = same_inner {
        return Ok(inner == peer);
    }
    if !is_set_like(other)? {
        return Ok(false);
    }
    let Ok(other_len) = other.len() else {
        return Ok(false);
    };
    if other_len != inner.len() {
        return Ok(false);
    }
    for item in other.try_iter()? {
        let item = item?;
        let probe = ProbeKey::from_bound(&item)?;
        if !inner.contains(probe.as_key()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Emits one Python-facing set surface (class + element iterator) per backend.
/// Mirrors `define_map_classes!`: invoked once each for `Elastic` and `Funnel`.
macro_rules! define_set_classes {
    (
        py_set = $PySet:ident,
        py_set_name = $py_set_name:literal,
        inner = $Inner:ident,
        validate_rf = $validate_rf:ident,
        key_iter = $KeyIter:ident,
        key_iter_name = $key_iter_name:literal,
    ) => {
        /// `PyO3` wrapper around the Rust hash set.
        #[pyclass(name = $py_set_name, module = "opthash")]
        struct $PySet {
            inner: $Inner<HashedAny>,
            /// Mutation counter snapshotted by iterators; mismatch on
            /// `__next__` raises `RuntimeError`.
            generation: u64,
        }

        impl $PySet {
            /// Invalidate active iterator snapshots. Call after every mutation.
            #[inline]
            fn bump(&mut self) {
                self.generation = self.generation.wrapping_add(1);
            }

            #[inline]
            fn bump_if_changed(&mut self, changed: bool) {
                if changed {
                    self.bump();
                }
            }

            /// Inserts every element of `other` (an opthash set or any iterable).
            /// Returns whether the set changed.
            fn add_all(&mut self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_add_all, &mut self.inner, other)
            }

            /// Removes every element of `other` from the set. Returns whether
            /// the set changed.
            fn remove_all(&mut self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_remove_all, &mut self.inner, other)
            }

            /// Retains only the elements also present in `other`. Returns
            /// whether the set changed.
            fn retain_in(&mut self, other: &Bound<PyAny>, py: Python) -> PyResult<bool> {
                dispatch_same_type!(set_retain_in, &mut self.inner, other, py)
            }

            /// In-place symmetric difference with `other`.
            fn symmetric_difference_with(&mut self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_symmetric_difference_with, &mut self.inner, other)
            }
        }

        #[pymethods]
        impl $PySet {
            #[new]
            #[pyo3(signature = (iterable = None, *, capacity = 0))]
            fn new(iterable: Option<&Bound<PyAny>>, capacity: usize) -> PyResult<Self> {
                let mut me = Self {
                    inner: $Inner::with_capacity(capacity),
                    generation: 0,
                };
                if let Some(iterable) = iterable {
                    me.add_all(iterable)?;
                }
                Ok(me)
            }

            #[classmethod]
            #[pyo3(signature = (capacity = 0, reserve_fraction = None))]
            fn with_options(
                _cls: &Bound<PyType>,
                capacity: usize,
                reserve_fraction: Option<f64>,
            ) -> PyResult<Self> {
                let rf = $validate_rf(reserve_fraction)?;
                Ok(Self {
                    inner: $Inner::with_capacity_and_reserve_fraction(capacity, rf),
                    generation: 0,
                })
            }

            /// Runtime support for `Cls[T]` via `types.GenericAlias`.
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

            fn __contains__(&self, value: &Bound<PyAny>) -> PyResult<bool> {
                let probe = ProbeKey::from_bound(value)?;
                Ok(self.inner.contains(probe.as_key()))
            }

            fn __iter__(slf: Bound<Self>) -> $KeyIter {
                let py = slf.py();
                let m = slf.borrow();
                let snapshot = m.inner.iter().map(|k| Some(k.obj_clone_ref(py))).collect();
                let expected_gen = m.generation;
                drop(m);
                $KeyIter {
                    map: slf.unbind(),
                    snapshot,
                    expected_gen,
                    pos: 0,
                }
            }

            fn __repr__(&self) -> String {
                format!(
                    concat!($py_set_name, "(len={}, capacity={})"),
                    self.inner.len(),
                    self.inner.capacity()
                )
            }

            fn copy(&self, py: Python) -> Self {
                let mut new = $Inner::with_capacity(self.inner.len());
                for value in self.inner.iter() {
                    new.insert(value.clone_with_py(py));
                }
                Self {
                    inner: new,
                    generation: 0,
                }
            }

            fn add(&mut self, value: &Bound<PyAny>) -> PyResult<()> {
                let key = HashedAny::from_bound(value)?;
                if self.inner.insert(key) {
                    self.bump();
                }
                Ok(())
            }

            fn discard(&mut self, value: &Bound<PyAny>) -> PyResult<()> {
                let probe = ProbeKey::from_bound(value)?;
                if self.inner.remove(probe.as_key()) {
                    self.bump();
                }
                Ok(())
            }

            fn remove(&mut self, value: &Bound<PyAny>) -> PyResult<()> {
                let probe = ProbeKey::from_bound(value)?;
                if self.inner.remove(probe.as_key()) {
                    self.bump();
                    Ok(())
                } else {
                    Err(missing_key(value))
                }
            }

            fn pop(&mut self, py: Python) -> PyResult<Py<PyAny>> {
                if self.inner.is_empty() {
                    return Err(PyKeyError::new_err("pop from an empty set"));
                }
                // `extract_if` removes only the elements it yields (its `Drop` is
                // a no-op), so taking one leaves the rest intact.
                let value = self.inner.extract_if(|_| true).next().expect("len > 0");
                let obj = value.obj_clone_ref(py);
                self.bump();
                Ok(obj)
            }

            fn clear(&mut self) {
                Python::attach(|_py| self.inner.clear());
                self.bump();
            }

            fn isdisjoint(&self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_isdisjoint, &self.inner, other)
            }

            fn issubset(&self, other: &Bound<PyAny>, py: Python) -> PyResult<bool> {
                dispatch_same_type!(set_issubset, &self.inner, other, py)
            }

            fn issuperset(&self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_issuperset, &self.inner, other)
            }

            #[pyo3(signature = (*others))]
            fn union(&self, others: &Bound<PyTuple>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                for other in others.try_iter()? {
                    new.add_all(&other?)?;
                }
                Ok(new)
            }

            #[pyo3(signature = (*others))]
            fn intersection(&self, others: &Bound<PyTuple>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                for other in others.try_iter()? {
                    new.retain_in(&other?, py)?;
                }
                Ok(new)
            }

            #[pyo3(signature = (*others))]
            fn difference(&self, others: &Bound<PyTuple>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                for other in others.try_iter()? {
                    new.remove_all(&other?)?;
                }
                Ok(new)
            }

            fn symmetric_difference(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                new.symmetric_difference_with(other)?;
                Ok(new)
            }

            #[pyo3(signature = (*others))]
            fn update(&mut self, others: &Bound<PyTuple>) -> PyResult<()> {
                let mut touched = false;
                for other in others.try_iter()? {
                    touched |= self.add_all(&other?)?;
                }
                self.bump_if_changed(touched);
                Ok(())
            }

            #[pyo3(signature = (*others))]
            fn intersection_update(&mut self, others: &Bound<PyTuple>, py: Python) -> PyResult<()> {
                let mut touched = false;
                for other in others.try_iter()? {
                    touched |= self.retain_in(&other?, py)?;
                }
                self.bump_if_changed(touched);
                Ok(())
            }

            #[pyo3(signature = (*others))]
            fn difference_update(&mut self, others: &Bound<PyTuple>) -> PyResult<()> {
                let mut touched = false;
                for other in others.try_iter()? {
                    touched |= self.remove_all(&other?)?;
                }
                self.bump_if_changed(touched);
                Ok(())
            }

            fn symmetric_difference_update(&mut self, other: &Bound<PyAny>) -> PyResult<()> {
                let touched = self.symmetric_difference_with(other)?;
                self.bump_if_changed(touched);
                Ok(())
            }

            fn __eq__(&self, other: &Bound<PyAny>) -> PyResult<bool> {
                dispatch_same_type!(set_eq, &self.inner, other)
            }

            fn __or__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                new.add_all(other)?;
                Ok(new)
            }

            fn __ror__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                // Union is commutative for membership; result keeps this backend.
                self.__or__(other, py)
            }

            fn __and__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                new.retain_in(other, py)?;
                Ok(new)
            }

            fn __rand__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                self.__and__(other, py)
            }

            fn __sub__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                let mut new = self.copy(py);
                new.remove_all(other)?;
                Ok(new)
            }

            fn __rsub__(&self, other: &Bound<PyAny>) -> PyResult<Self> {
                // `other - self`: start from `other`, drop everything in `self`.
                let mut new = Self {
                    inner: $Inner::new(),
                    generation: 0,
                };
                new.add_all(other)?;
                for value in self.inner.iter() {
                    new.inner.remove(value);
                }
                Ok(new)
            }

            fn __xor__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                self.symmetric_difference(other, py)
            }

            fn __rxor__(&self, other: &Bound<PyAny>, py: Python) -> PyResult<Self> {
                self.symmetric_difference(other, py)
            }

            fn __ior__(&mut self, other: &Bound<PyAny>) -> PyResult<()> {
                if self.add_all(other)? {
                    self.bump();
                }
                Ok(())
            }

            fn __iand__(&mut self, other: &Bound<PyAny>, py: Python) -> PyResult<()> {
                if self.retain_in(other, py)? {
                    self.bump();
                }
                Ok(())
            }

            fn __isub__(&mut self, other: &Bound<PyAny>) -> PyResult<()> {
                if self.remove_all(other)? {
                    self.bump();
                }
                Ok(())
            }

            fn __ixor__(&mut self, other: &Bound<PyAny>) -> PyResult<()> {
                if self.symmetric_difference_with(other)? {
                    self.bump();
                }
                Ok(())
            }
        }

        define_iter!($KeyIter, $key_iter_name, $PySet);
    };
}

define_set_classes! {
    py_set = PyElasticHashSet,
    py_set_name = "ElasticHashSet",
    inner = ElasticHashSet,
    validate_rf = validate_elastic_reserve_fraction,
    key_iter = PyElasticSetIter,
    key_iter_name = "_ElasticSetIter",
}

define_set_classes! {
    py_set = PyFunnelHashSet,
    py_set_name = "FunnelHashSet",
    inner = FunnelHashSet,
    validate_rf = validate_funnel_reserve_fraction,
    key_iter = PyFunnelSetIter,
    key_iter_name = "_FunnelSetIter",
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
fn opthash(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyElasticHashMap>()?;
    m.add_class::<PyFunnelHashMap>()?;
    m.add_class::<PyElasticHashSet>()?;
    m.add_class::<PyFunnelHashSet>()?;
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
