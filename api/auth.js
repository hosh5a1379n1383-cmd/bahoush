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

    if (!appToken) {
      return res.status(500).json({
        ok: false,
        error: "EITAA_APP_TOKEN تنظیم نشده است"
      });
    }

    if (!supabaseUrl || !supabaseSecretKey) {
      return res.status(500).json({
        ok: false,
        error: "تنظیمات Supabase کامل نیست"
      });
    }

    // =========================
    // بررسی اعتبار اطلاعات ایتا
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
    // بررسی تاریخ ورود
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
    // دریافت اطلاعات کاربر
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
    // بررسی هنرجو در Supabase
    // =========================

    const studentUrl =
      `${supabaseUrl}/rest/v1/students` +
      `?eitaa_user_id=eq.${encodeURIComponent(user.id)}` +
      `&select=id,eitaa_user_id,first_name,last_name,username,is_active,has_access`;

    const studentResponse = await fetch(studentUrl, {
      method: "GET",
      headers: {
        "apikey": supabaseSecretKey,
        "Authorization": `Bearer ${supabaseSecretKey}`
      }
    });

    if (!studentResponse.ok) {
      console.error(
        "Supabase Error:",
        await studentResponse.text()
      );

      return res.status(500).json({
        ok: false,
        error: "خطا در بررسی اطلاعات هنرجو"
      });
    }

    const students = await studentResponse.json();

    const student = students[0] || null;

    // =========================
    // پاسخ نهایی
    // =========================

    if (!student) {
      return res.status(200).json({
        ok: true,
        registered: false,
        hasAccess: false,
        user: {
          id: user.id,
          first_name: user.first_name || "",
          last_name: user.last_name || "",
          username: user.username || ""
        }
      });
    }

    return res.status(200).json({
      ok: true,
      registered: true,
      hasAccess: student.is_active && student.has_access,
      user: {
        id: user.id,
        first_name: student.first_name || user.first_name || "",
        last_name: student.last_name || user.last_name || "",
        username: student.username || user.username || ""
      }
    });

  } catch (error) {
    console.error("Auth Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور"
    });
  }
};
