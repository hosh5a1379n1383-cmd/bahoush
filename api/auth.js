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

    // بررسی ادمین
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
    const isAdmin = admins.length > 0;

    // بررسی هنرجو
    const studentUrl =
      `${supabaseUrl}/rest/v1/students` +
      `?eitaa_user_id=eq.${encodeURIComponent(user.id)}` +
      `&select=id,eitaa_user_id,first_name,last_name,username,is_active,has_access`;

    const studentResponse = await fetch(studentUrl, {
      method: "GET",
      headers
    });

    if (!studentResponse.ok) {
      console.error("Student Error:", await studentResponse.text());

      return res.status(500).json({
        ok: false,
        error: "خطا در بررسی اطلاعات هنرجو"
      });
    }

    const students = await studentResponse.json();
    const student = students[0] || null;

    // دریافت آموزش‌ها
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
      console.error("Lessons Error:", await lessonsResponse.text());

      return res.status(500).json({
        ok: false,
        error: "خطا در دریافت آموزش‌ها"
      });
    }

    const lessons = await lessonsResponse.json();

    return res.status(200).json({

      ok: true,

      registered: !!student,

      hasAccess: !!(
        student &&
        student.is_active &&
        student.has_access
      ),

      isAdmin,

      user: {
        id: user.id,
        first_name: student?.first_name || user.first_name || "",
        last_name: student?.last_name || user.last_name || "",
        username: student?.username || user.username || ""
      },

      lessons

    });

  } catch (error) {

    console.error("Auth Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور"
    });

  }

};
