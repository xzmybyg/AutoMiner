const paths: Record<string, string> = {
  targets:
    "M20 13V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h7M8 7h8M8 11h5M16 18l2 2 4-4",
  testing: "M8 4H4v4M16 4h4v4M20 16v4h-4M8 20H4v-4M8 12h8M12 8v8",
  jobs: "M9 5h10a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4M9 3h6v4H9zM7 12h.01M11 12h6M7 16h.01M11 16h6",
  models: "M12 3l2.2 6.8L21 12l-6.8 2.2L12 21l-2.2-6.8L3 12l6.8-2.2z",
  findings: "M5 3h10l4 4v14H5zM14 3v5h5M8 12h8M8 16h6",
  shield: "M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6",
  refresh:
    "M20 7v5h-5M4 17v-5h5M5.5 7a7 7 0 0 1 11.6-2L20 8M4 16l2.9 3A7 7 0 0 0 18.5 17",
};

export function WorkspaceIcon({ name }: { name: string }) {
  return (
    <svg
      className="workspace-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name] || paths.shield} />
    </svg>
  );
}
