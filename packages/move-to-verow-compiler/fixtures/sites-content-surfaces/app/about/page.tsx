const overview = {
  heading: 'Synthetic localized overview',
  body: 'Synthetic localized body',
} as const;

export default function AboutPage() {
  return <article id="overview"><h1>{overview.heading}</h1></article>;
}
