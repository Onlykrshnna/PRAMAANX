import {
  Nav,
  Hero,
  TrustStrip,
  Features,
  Stats,
  Steps,
  Limits,
  FinalCta,
} from '../components/landing';

export default function Home() {
  return (
    <div className="min-h-screen bg-[var(--bg-canvas)] text-[var(--text-primary)] transition-colors duration-200">
      {/* 1. Nav */}
      <Nav />

      {/* Main Section Content Canvas */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* 2. Hero */}
        <Hero />

        {/* 3. TrustStrip */}
        <TrustStrip />

        {/* 4. Features */}
        <Features />

        {/* 5. Stats */}
        <Stats />

        {/* 6. Steps */}
        <Steps />

        {/* 7. Limits */}
        <Limits />
      </main>

      {/* 8. FinalCta */}
      <FinalCta />
    </div>
  );
}
