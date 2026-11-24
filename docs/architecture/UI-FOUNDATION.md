# UI Foundation

## Experience structure

The web application is organized around a persistent workspace shell:

- **Sidebar:** workspace identity, grouped navigation, and system destinations.
- **Top bar:** current location, workspace search, assistant entry point, and notifications.
- **Overview:** security posture summary, risk distribution, score trend, prioritized findings, and recent activity.
- **Module landing states:** communicate planned destinations without implying those workflows are already implemented.

## Component boundaries

- `components/layout`: persistent navigation and top-level workspace chrome.
- `components/dashboard`: overview-specific cards, charts, and tables.
- `App.tsx`: lightweight route-selection state for the current shell.

As modules grow, move route state to a router and share query/data contracts through dedicated packages rather than coupling domain logic to presentation components.

## Interaction and accessibility

- Navigation uses native buttons with visible active states.
- Search is a controlled input and filters the sample finding list.
- Tables use semantic table elements and explicit column headers.
- Informative visualizations include accessible labels or supporting legends.
- Decorative visual layers are not used to convey unique information.
- Reduced-motion preferences are respected.

## Data integrity

The current dashboard intentionally uses static, illustrative sample records. It must not be presented as live security telemetry. Future API-backed metrics should include source, freshness timestamp, tenant scope, and clear unavailable/stale states.

## Responsive behavior

- Desktop: full workspace navigation and multi-column dashboard.
- Tablet: compact icon navigation and stacked analytical panels.
- Mobile: compact top bar, two-column metric cards, and horizontally scrollable findings table.

## Follow-on work

Connect authenticated workspace context, replace sample metrics with tenant-scoped API queries, introduce loading/error/empty states, and add visual regression plus keyboard navigation tests.
