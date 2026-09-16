module.exports = async (req, res) => {

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      error: "Method Not Allowed"
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabasePublishableKey =
    process.env.SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !supabasePublishableKey) {
    return res.status(500).json({
      ok: false,
      error: "تنظیمات Supabase کامل نیست"
    });
  }

  return res.status(200).json({
    ok: true,
    supabaseUrl,
    supabasePublishableKey
  });
};
