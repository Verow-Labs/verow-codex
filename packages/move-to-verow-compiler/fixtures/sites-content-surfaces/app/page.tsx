const hero = {
  heading: 'Synthetic migration heading',
  richText: '<p>Synthetic <strong>rich text</strong>.</p>',
  primaryCta: {
    label: 'Synthetic action',
    href: '/synthetic-destination',
  },
} as const;

const contact = {
  email: 'synthetic@example.invalid',
  emailHref: 'mailto:synthetic@example.invalid',
  telephone: '+1 555 0100',
  telephoneHref: 'tel:+15550100',
} as const;

const editorialImage = {
  src: '/synthetic-editorial.jpg',
  alt: 'Synthetic editorial description',
  caption: 'Synthetic editorial caption',
} as const;

const inquiryForm = {
  nameLabel: 'Synthetic name label',
  namePlaceholder: 'Synthetic placeholder',
  nameHelp: 'Synthetic form help',
  successMessage: 'Synthetic success message',
  validationMessage: 'Synthetic validation message',
} as const;

const map = {
  heading: 'Synthetic map wrapper heading',
  fallbackText: 'Synthetic map fallback',
} as const;

export const metadata = {
  title: 'Synthetic metadata title',
  description: 'Synthetic metadata description',
  openGraph: {
    title: 'Synthetic Open Graph title',
    description: 'Synthetic Open Graph description',
  },
} as const;

export default function HomePage() {
  return (
    <main aria-label="Synthetic main landmark">
      <section id="intro">
        <p data-verow-field="richText">Synthetic JSX <strong>rich text</strong>.</p>
      </section>
      <section id="ordinary">
        <h2>Synthetic ordinary heading</h2>
        <p>Synthetic ordinary <em>rich text</em>.</p>
      </section>
      <section id="hero"><a href={hero.primaryCta.href}>{hero.primaryCta.label}</a></section>
      <img src={editorialImage.src} alt={editorialImage.alt} />
      <img data-verow-role="featureImage" src="/synthetic-feature.jpg" alt="Synthetic feature image description" />
      <a data-verow-role="secondaryCta" href="/synthetic-secondary" title="Synthetic secondary title">Synthetic secondary action</a>
      <input data-verow-role="search" placeholder="Synthetic search placeholder" />
      <form action="/api/inquiry"><label>{inquiryForm.nameLabel}<input placeholder={inquiryForm.namePlaceholder} /></label></form>
      <section id="map"><h2>{map.heading}</h2><MapWidget data-verow-boundary="map.widget" data-verow-provider="maps.example" data-verow-integration="synthetic-map" /></section>
      <span data-verow-role="copyright" data-verow-field="year" data-verow-derived-from="system.currentYear">{new Date().getFullYear()}</span>
      <img data-verow-role="decoration" src="/synthetic-texture.svg" aria-hidden="true" />
    </main>
  );
}
