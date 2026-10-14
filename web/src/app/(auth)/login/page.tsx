"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { auth } from "@/lib/auth";

export default function LoginPage() {
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    // The Go server owns the OIDC handshake. This static fallback must not
    // render the retired ARTEX password form if reached directly.
    auth
      .checkSession()
      .then((ok) => {
        window.location.assign(ok ? "/function/tasks" : "/auth/login");
      })
      .catch(() => setError("鉴权服务暂时不可用，请稍后重试"))
      .finally(() => setChecking(false));
  }, []);

  return (
    <main className="flex min-h-dvh items-center justify-center p-8">
      <div className="w-full max-w-sm space-y-4 text-center">
        <h1 className="text-2xl font-medium">ARTEX 私有控制台</h1>
        {checking ? <p className="text-muted-foreground">正在跳转统一登录…</p> : null}
        {error ? (
          <>
            <p className="text-sm text-destructive">{error}</p>
            <Button type="button" onClick={() => window.location.reload()}>
              重试
            </Button>
          </>
        ) : null}
      </div>
    </main>
  );
}
