"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    auth
      .checkSession()
      .then((ok) => {
        window.location.assign(ok ? "/function/tasks" : "/auth/login");
      })
      .catch(() => setError("ARTEX 仅支持统一登录，无法使用本地初始化"))
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
            <Button type="button" onClick={() => window.location.assign("/auth/login")}>
              使用统一登录
            </Button>
          </>
        ) : null}
      </div>
    </main>
  );
}
