const API_ROOT = "/api/v1";
const TOKEN_KEY = "micepp_access_token";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const auth = {
  token: () => localStorage.getItem(TOKEN_KEY),
  set: (token: string) => localStorage.setItem(TOKEN_KEY, token),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  const token = auth.token();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  if (response.status === 401) auth.clear();
  if (!response.ok) {
    let message = `Erreur HTTP ${response.status}`;
    try {
      const payload = await response.json();
      message = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail ?? payload);
    } catch { /* réponse non JSON */ }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<void> {
  const body = new URLSearchParams({ username, password });
  const response = await fetch(`${API_ROOT}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) throw new ApiError(response.status, "Identifiants invalides");
  const payload = await response.json();
  auth.set(payload.access_token);
}

export async function downloadReport(jobId: string): Promise<void> {
  const response = await fetch(`${API_ROOT}/jobs/${jobId}/report`, {
    headers: { Authorization: `Bearer ${auth.token()}` },
  });
  if (!response.ok) throw new ApiError(response.status, "Rapport indisponible");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `rapport-${jobId}.pdf`;
  anchor.click();
  URL.revokeObjectURL(url);
}

