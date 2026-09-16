const crypto = require("crypto");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "Method Not Allowed"
    });
  }

  try {
    const { initData, fileName, contentType } = req.body || {};

    if (!initData) {
      return res.status(400).json({
        ok: false,
        error: "initData ارسال نشده است"
      });
    }

    if (!fileName || !contentType) {
      return res.status(400).json({
        ok: false,
        error: "اطلاعات فایل کامل نیست"
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

    // =========================
    // اعتبارسنجی ایتا
    // =========================

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

    // =========================
    // بررسی زمان ورود
    // =========================

    const authDate = Number(params.get("auth_date"));

    if (!authDate) {
      return res.status(401).json({
        ok: false,
        error: "auth_date وجود ندارد"
      });
    }

    const currentTime = Math.floor(Date.now() / 1000);

    if (currentTime - authDate > 86400) {
      return res.status(401).json({
        ok: false,
        error: "اطلاعات ورود منقضی شده است"
      });
    }

    // =========================
    // دریافت کاربر
    // =========================

    const userData = params.get("user");

    if (!userData) {
      return res.status(401).json({
        ok: false,
        error: "اطلاعات کاربر وجود ندارد"
      });
    }

    const user = JSON.parse(userData);

    // =========================
    // بررسی ادمین
    // =========================

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
      console.error("Admin Error:", await adminResponse.text());

      return res.status(500).json({
        ok: false,
        error: "خطا در بررسی ادمین"
      });
    }

    const admins = await adminResponse.json();

    if (!admins.length) {
      return res.status(403).json({
        ok: false,
        error: "شما اجازه آپلود ندارید"
      });
    }

    // =========================
    // ساخت نام امن فایل
    // =========================

    const cleanFileName = fileName
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .replace(/\s+/g, "_");

    const uniqueName =
      `${Date.now()}_${crypto.randomBytes(6).toString("hex")}_${cleanFileName}`;

    const filePath = `lessons/${uniqueName}`;

    // =========================
    // ساخت Signed Upload URL
    // =========================

    const signUrl =
      `${supabaseUrl}/storage/v1/object/upload/sign/course-videos/${encodeURIComponent(filePath)}`;

    const signResponse = await fetch(signUrl, {
      method: "POST",
      headers: {
        ...headers,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        upsert: false
      })
    });

    if (!signResponse.ok) {
      const errorText = await signResponse.text();

      console.error("Storage Error:", errorText);

      return res.status(500).json({
        ok: false,
        error: "خطا در ساخت لینک آپلود"
      });
    }

    const signData = await signResponse.json();

    return res.status(200).json({
      ok: true,
      path: filePath,
      token: signData.token,
      contentType
    });

  } catch (error) {

    console.error("Upload URL Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور"
    });
  }
};
