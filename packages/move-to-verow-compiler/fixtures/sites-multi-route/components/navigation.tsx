import Link from 'next/link';

export function Navigation() {
  return (
    <nav aria-label="Fixture navigation">
      <Link href="/">Home</Link>
      <Link href="/about">About</Link>
    </nav>
  );
}
