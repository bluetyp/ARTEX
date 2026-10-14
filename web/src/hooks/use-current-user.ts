"use client";

import { useEffect, useState } from "react";

import { auth, type CurrentUser } from "@/lib/auth";

const FALLBACK: CurrentUser = { id: "1", name: "ARTEX", username: "artex", email: "", avatar: "", role: "operator" };

export function useCurrentUser(): CurrentUser {
  const [user, setUser] = useState<CurrentUser>(() => auth.getCurrentUser() ?? FALLBACK);

  useEffect(() => {
    let active = true;
    auth.checkSession().then((ok) => {
      if (!active || !ok) return;
      const u = auth.getCurrentUser();
      if (u) setUser(u);
    }).catch(() => {
      // The main layout renders the authoritative authentication error.
    });
    return () => { active = false; };
  }, []);

  return user;
}
