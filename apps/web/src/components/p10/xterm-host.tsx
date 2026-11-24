'use client';

/**
 * xterm.js + fit addon, client-only (loaded with next/dynamic ssr:false). Output is written verbatim:
 * command output is never translated or rewritten. Keys go straight to the SSH session except F6, which
 * moves focus out of the terminal to its toolbar (the terminal otherwise captures Tab).
 */
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

export interface XtermHandle {
  write(data: Uint8Array | string): void;
  clear(): void;
  focus(): void;
  fit(): void;
  size(): { cols: number; rows: number };
  setScreenReader(on: boolean): void;
}

export default function XtermHost({
  label,
  onHandle,
  onInput,
  onResize,
  onEscapeFocus,
}: {
  label: string;
  onHandle: (h: XtermHandle | null) => void;
  onInput: (data: string | Uint8Array) => void;
  onResize: (cols: number, rows: number) => void;
  onEscapeFocus: () => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  // keep the latest callbacks without re-creating the terminal
  const cb = useRef({ onInput, onResize, onEscapeFocus, onHandle });
  cb.current = { onInput, onResize, onEscapeFocus, onHandle };

  const labelRef = useRef(label);
  labelRef.current = label;

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    // Create on the next tick: under React StrictMode the first mount is torn down synchronously, and
    // xterm 5.5 schedules a viewport refresh in its constructor that throws if it was already disposed.
    let teardown: (() => void) | null = null;
    const timer = setTimeout(() => {
      teardown = init(el);
    }, 0);
    return () => {
      clearTimeout(timer);
      teardown?.();
    };
  }, []);

  function init(el: HTMLDivElement): () => void {
    const term = new Terminal({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      scrollback: 5000,
      allowProposedApi: false,
      theme: { background: '#17181a', foreground: '#e8e8e6', cursor: '#e8e8e6' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    termRef.current = term;
    term.textarea?.setAttribute('aria-label', labelRef.current);
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === 'keydown' && e.key === 'F6') {
        e.preventDefault();
        cb.current.onEscapeFocus();
        return false;
      }
      return true;
    });
    const safeFit = () => {
      try {
        if (el.offsetParent !== null && fit.proposeDimensions()) fit.fit();
      } catch {
        /* not laid out yet */
      }
    };
    safeFit();
    const d1 = term.onData((s) => cb.current.onInput(s));
    const d2 = term.onBinary((s) => {
      const b = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
      cb.current.onInput(b);
    });
    const d3 = term.onResize(({ cols, rows }) => cb.current.onResize(cols, rows));
    const ro = new ResizeObserver(() => safeFit());
    ro.observe(el);
    const handle: XtermHandle = {
      write: (d) => term.write(d),
      clear: () => term.reset(),
      focus: () => term.focus(),
      fit: safeFit,
      size: () => ({ cols: term.cols, rows: term.rows }),
      setScreenReader: (on) => {
        term.options.screenReaderMode = on;
      },
    };
    cb.current.onHandle(handle);
    return () => {
      cb.current.onHandle(null);
      ro.disconnect();
      d1.dispose();
      d2.dispose();
      d3.dispose();
      termRef.current = null;
      term.dispose();
    };
  }

  useEffect(() => {
    termRef.current?.textarea?.setAttribute('aria-label', label);
  }, [label]);

  return <div ref={box} className="h-full w-full" data-testid="xterm" />;
}
