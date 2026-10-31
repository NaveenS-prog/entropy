"use client";

import Image from "next/image";

interface EntropyLogoProps {
  size?: number;
  className?: string;
  roundedClassName?: string;
  priority?: boolean;
}

export function EntropyLogo({
  size = 32,
  className = "",
  roundedClassName = "rounded-lg",
  priority = false,
}: EntropyLogoProps) {
  return (
    <div
      className={`relative inline-flex items-center justify-center overflow-hidden shrink-0 ${roundedClassName} ${className}`}
      style={{ width: size, height: size }}
    >
      <Image
        src="/entropy-icon-square.png"
        alt="Entropy Logo"
        width={size}
        height={size}
        className="w-full h-full object-cover"
        priority={priority}
      />
    </div>
  );
}
