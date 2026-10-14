const TOKEN_KEY = "artex_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

let ssoMode = false;
let ssoUser: CurrentUser | null = null;

export const auth = {
  isSSO(): boolean {
    return ssoMode;
  },

  async checkSession(): Promise<boolean> {
    const status = await fetch("/api/auth/status", { cache: "no-store" });
    if (!status.ok) throw new Error("鉴权服务暂时不可用，请稍后刷新");
    const config = await status.json();
    ssoMode = config.mode === "oidc";
    if (!ssoMode) return Boolean(this.getToken());
    // SSO credentials stay in the server-side session, never localStorage.
    this.clearToken();
    const response = await fetch("/auth/me", { cache: "no-store" });
    if (response.status === 401) return false;
    if (response.status === 403) throw new Error("此账号未获授权访问 ARTEX");
    if (!response.ok) throw new Error("鉴权服务暂时不可用，请稍后刷新");
    ssoUser = await response.json();
    return true;
  },

  async logout(): Promise<void> {
    if (ssoMode) {
      const response = await fetch("/auth/logout", { method: "POST" });
      if (!response.ok) throw new Error("退出失败，请稍后重试");
      this.clearToken();
      window.location.assign("/auth/logged-out");
      return;
    }
    this.clearToken();
    window.location.assign("/login");
  },

  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // 同步写 cookie，供 Next.js middleware 服务端读取
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    if (ssoMode) return ssoUser;
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "ARTEX";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};
