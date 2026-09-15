/**
 * The Zypher mark.
 *
 * A geometric Z cut from a shield: the shield says what the product is for, the
 * Z says which product it is, and neither needs a colour to be legible. Drawn
 * rather than imported so it inherits currentColor, stays sharp at any size and
 * adds nothing to the bundle — this ships as an offline desktop app, where a
 * remote icon font is simply a broken image.
 *
 * The strokes are on a 24-unit grid with a single stroke weight, which is what
 * keeps it sitting correctly beside Lucide glyphs at the same optical size.
 */
import React from 'react';

export function ZypherMark({ className = 'h-5 w-5', title }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : 'true'}
      aria-label={title}
      fill="none"
    >
      {title && <title>{title}</title>}
      {/* Shield silhouette */}
      <path
        d="M12 2.6 20 5.4v6.1c0 4.7-3.2 8.6-8 9.9-4.8-1.3-8-5.2-8-9.9V5.4L12 2.6Z"
        fill="currentColor"
        opacity="0.14"
      />
      <path
        d="M12 2.6 20 5.4v6.1c0 4.7-3.2 8.6-8 9.9-4.8-1.3-8-5.2-8-9.9V5.4L12 2.6Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* The Z, drawn as three strokes so the diagonal keeps an even weight */}
      <path
        d="M8.6 8.4h6.8L8.6 15.2h6.8"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * The full lock-up: mark, wordmark and the line that says what this is.
 *
 * `subdued` renders the descriptor in the muted tone for places where the
 * wordmark is a label rather than a masthead.
 */
export function ZypherWordmark({ badge }) {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="flex h-9 w-9 items-center justify-center rounded-[9px]"
        style={{ background: 'var(--solid)', color: 'var(--on-solid)' }}
      >
        <ZypherMark className="h-[19px] w-[19px]" />
      </div>
      <div className="leading-tight">
        <div className="flex items-center gap-1.5">
          <span
            className="text-[15px] font-semibold"
            style={{ letterSpacing: '-0.02em' }}
          >
            Zypher
          </span>
          {badge}
        </div>
        <div className="text-[10.5px] text-faint" style={{ letterSpacing: '0.01em' }}>
          Cryptographic discovery
        </div>
      </div>
    </div>
  );
}
