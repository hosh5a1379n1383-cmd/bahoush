const crypto = require("crypto");

module.exports = async (req, res) => {

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "Method Not Allowed"
    });
  }

  try {

    const { initData } = req.body || {};

    if (!initData) {
      return res.status(400).json({
        ok: false,
        error: "initData ارسال نشده است"
      });
    }

    const appToken = process.env.EITAA_APP_TOKEN;
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

    if (!appToken || !supabaseUrl || !supabaseSecretKey) {
      return res.status(500).json({
        ok: false,
        error: "تنظیمات سرور کامل نیست"
      });
    }

    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash) {
      return res.status(401).json({
        ok: false,
        error: "hash وجود ندارد"
      });
    }

    params.delete("hash");

    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(appToken)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    if (calculatedHash !== receivedHash) {
      return res.status(401).json({
        ok: false,
        error: "اعتبارسنجی ایتا ناموفق بود"
      });
    }

    const userData = params.get("user");

    if (!userData) {
      return res.status(401).json({
        ok: false,
        error: "اطلاعات کاربر وجود ندارد"
      });
    }

    const user = JSON.parse(userData);

    // فقط تست خواندن جدول admins
    const adminUrl =
      `${supabaseUrl}/rest/v1/admins` +
      `?eitaa_user_id=eq.${encodeURIComponent(user.id)}` +
      `&is_active=eq.true` +
      `&select=id,eitaa_user_id,is_active`;

    const adminResponse = await fetch(adminUrl, {
      method: "GET",
      headers: {
        "apikey": supabaseSecretKey,
        "Authorization": `Bearer ${supabaseSecretKey}`
      }
    });

    if (!adminResponse.ok) {

      const errorText = await adminResponse.text();

      console.error("Supabase Admin Error:", errorText);

      return res.status(500).json({
        ok: false,
        error: "خواندن جدول admins ناموفق بود",
        details: errorText
      });
    }

    const admins = await adminResponse.json();

    return res.status(200).json({
      ok: true,
      message: "خواندن جدول admins موفق بود ✅",
      userId: user.id,
      adminsFound: admins.length,
      admins: admins
    });

  } catch (error) {

    console.error("Auth Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور",
      details: error.message
    });

  }
};
