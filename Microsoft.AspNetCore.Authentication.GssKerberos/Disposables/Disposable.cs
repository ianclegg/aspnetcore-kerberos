using System;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Disposables
{
    /// <summary>
    /// Automatic dynamic disposable
    /// </summary>
    public static class Disposable
    {
        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>
        /// </summary> 
        public static Disposable<T> From<T>(T value) =>
            From(value, (IDisposable[])null, (Action)null);

        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposeAction"/> will be called at dispose
        /// </summary>
        public static Disposable<T> From<T>(T value, Action disposeAction) =>
            From(value, null, disposeAction);

        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposable"/> will be disposed
        /// </summary>
        public static Disposable<T> From<T, D>(D disposable, Func<D, T> loader) where D : IDisposable =>
            From(loader(disposable), disposable);
        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposable"/> will be disposed
        /// </summary>
        public static Disposable<T> From<T, D>(D disposable, Func<D, T> loader, Action<T> disposer) where D : IDisposable =>
            From(loader(disposable), disposable);

        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposables"/> will be disposed
        /// </summary>
        public static Disposable<T> From<T>(T value, params IDisposable[] disposables) =>
            From(value, disposables, null);

        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposables"/> will be disposed and <paramref name="disposeAction"/> will be called at dispose
        /// </summary>
        public static Disposable<T> From<T>(T value, IDisposable[] disposables, Action disposeAction) =>
            new Disposable<T>(value, disposables, disposeAction);
    }

    /// <summary>
    /// Automatic dynamic disposable
    /// </summary>
    public sealed class Disposable<T> : IDisposable
    {
        /// <summary>
        /// Original value, can be used with <code>ref</code>
        /// </summary>
        public T Value;

        private readonly IDisposable[] _disposables;
        private readonly Action _disposeAction;

        /// <summary>
        /// Automatic dynamic disposable storing <paramref name="value"/>, <paramref name="disposables"/> will be disposed and <paramref name="disposeAction"/> will be called at dispose
        /// </summary>
        public Disposable(T value, IDisposable[] disposables, Action disposeAction)
        {
            Value = value;
            _disposables = disposables;
            _disposeAction = disposeAction;
        }

        /// <summary>
        /// Returns stored value
        /// </summary>
        public static implicit operator T(Disposable<T> p)
        {
            return p.Value;
        }

        private bool _disposed = false;

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;

            if (_disposables != null)
                foreach (var t in _disposables)
                    t?.Dispose();

            _disposeAction?.Invoke();
        }
    }
}