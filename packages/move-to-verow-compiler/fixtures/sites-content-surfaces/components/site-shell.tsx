const header = {
  primaryNavigation: [
    { id: 'about', label: 'Synthetic about', href: '/about' },
    { id: 'contact', label: 'Synthetic contact', href: '/contact' },
  ],
} as const;

const footer = {
  contact: { email: 'footer@example.invalid', telephone: '+1 555 0101' },
  legal: { privacyLabel: 'Synthetic privacy label', privacyHref: '/privacy' },
  consentText: 'Synthetic consent wording',
} as const;

export function SiteShell() {
  return <><header aria-label="Synthetic primary navigation" /><footer>{footer.consentText}</footer></>;
}
