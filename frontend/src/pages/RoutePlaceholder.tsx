// Minimal route placeholder. Real pages arrive in later phases;
// this exists only so the route architecture can resolve and be tested.
interface RoutePlaceholderProps {
  title: string;
}

export function RoutePlaceholder({ title }: RoutePlaceholderProps) {
  return (
    <main className="bg-background text-text-primary">
      <h1>{title}</h1>
    </main>
  );
}
