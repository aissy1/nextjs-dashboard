import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import { sql } from "@vercel/postgres";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        try {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);

          if (!parsedCredentials.success) {
            console.log("Invalid input:", parsedCredentials.error);
            throw new Error(
              "Invalid input: Please provide valid email and password."
            );
          }

          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);

          if (!user) {
            console.log("User not found");
            return null;
          }

          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) {
            return { id: user.id, name: user.name, email: user.email };
          }

          console.log("Invalid password");
          return null;
        } catch (error) {
          console.error("Authorization error:", error);
          throw new Error("An error occurred during authentication.");
        }
      },
    }),
  ],
});
