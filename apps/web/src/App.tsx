export default function App() {
  return (
    <main className="shell">
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />
      <section className="hero" aria-labelledby="product-title">
        <div className="eyebrow"><span className="status-dot" /> FOUNDATION INITIALIZED</div>
        <div className="brand-mark" aria-hidden="true">C</div>
        <h1 id="product-title">Trust every release.</h1>
        <p className="intro">
          ChainProof is building a clearer, evidence-backed view of your software
          supply chain — from the first dependency to the artifact you deploy.
        </p>
        <div className="capabilities" aria-label="Platform capabilities">
          <span>SBOM intelligence</span>
          <span>Provenance verification</span>
          <span>Policy assurance</span>
        </div>
        <p className="footnote">Enterprise Software Supply Chain Security &amp; Trust Intelligence</p>
      </section>
    </main>
  );
}
