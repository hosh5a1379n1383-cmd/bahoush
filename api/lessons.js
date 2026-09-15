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

    const headers = {
      "apikey": supabaseSecretKey,
      "Authorization": `Bearer ${supabaseSecretKey}`
    };

    const adminUrl =
      `${supabaseUrl}/rest/v1/admins` +
      `?eitaa_user_id=eq.${encodeURIComponent(user.id)}` +
      `&is_active=eq.true` +
      `&select=id`;

    const adminResponse = await fetch(adminUrl, {
      method: "GET",
      headers
    });

    if (!adminResponse.ok) {
      return res.status(500).json({
        ok: false,
        error: "خطا در بررسی ادمین"
      });
    }

    const admins = await adminResponse.json();

    const isAdmin = admins.length > 0;

    const lessonsUrl =
      `${supabaseUrl}/rest/v1/lessons` +
      `?is_active=eq.true` +
      `&select=id,title,description,sort_order,content_type,content_url,publish_at` +
      `&order=sort_order.asc`;

    const lessonsResponse = await fetch(lessonsUrl, {
      method: "GET",
      headers
    });

    if (!lessonsResponse.ok) {
      console.error(
        "Supabase Lessons Error:",
        await lessonsResponse.text()
      );

      return res.status(500).json({
        ok: false,
        error: "خطا در دریافت آموزش‌ها"
      });
    }

    const lessons = await lessonsResponse.json();

    return res.status(200).json({
      ok: true,
      isAdmin,
      lessons
    });

  } catch (error) {

    console.error("Lessons Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور"
    });
  }
};
