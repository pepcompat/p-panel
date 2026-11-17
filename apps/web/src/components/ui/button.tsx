import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'dark' | 'link' | 'chip';
export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

const variants: Record<ButtonVariant, string> = {
  primary: 'border-0 bg-accent-strong text-on-accent font-medium hover:brightness-110 disabled:bg-fg-subtle',
  secondary: 'border border-line-strong bg-surface text-fg hover:bg-surface-hover disabled:bg-chip disabled:text-fg-subtle',
  ghost: 'border-0 bg-transparent text-fg-muted hover:text-fg disabled:text-fg-subtle',
  danger: 'border-0 bg-crit text-white font-medium hover:brightness-110 disabled:bg-fg-subtle',
  dark: 'border-0 bg-[#1c1d1f] text-white font-mono hover:bg-black disabled:bg-fg-subtle dark:bg-chip',
  link: 'border-0 bg-transparent p-0 text-link hover:text-link-hover hover:underline min-h-0',
  chip: 'border-0 bg-chip text-fg rounded-[3px] hover:bg-chip-2',
};
const sizes: Record<ButtonSize, string> = {
  xs: 'min-h-0 px-[7px] py-[2px] text-[11px]',
  sm: 'min-h-8 px-3 text-[12.5px]',
  md: 'min-h-9 px-3.5 text-[13.5px]',
  lg: 'min-h-[42px] px-4 text-[14px]',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', className, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded-md whitespace-nowrap transition-colors disabled:cursor-not-allowed',
        variants[variant],
        variant !== 'link' && sizes[size],
        variant === 'chip' && size === 'md' && sizes.xs,
        className,
      )}
      {...rest}
    />
  );
});
