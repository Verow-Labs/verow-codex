import Image from 'next/image';

export default function HomePage() {
  return (
    <main>
      <h1>Home route fixture</h1>
      <Image src="/fixture-mark.svg" alt="Fixture mark" width={48} height={48} priority />
    </main>
  );
}
