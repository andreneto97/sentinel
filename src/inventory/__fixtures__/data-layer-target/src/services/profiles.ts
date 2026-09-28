import { createClient } from "@supabase/supabase-js";

const supabase = createClient("https://example.supabase.co", "anon-key");

/** The caller's own bookings, through PostgREST. */
export async function myBookings(userId: string) {
  return await supabase.from("bookings").select("id,status").eq("user_id", userId).limit(10);
}

/** Every profile row, with no filter at all. */
export async function everyProfile() {
  return await supabase.from("profiles").select("*");
}
