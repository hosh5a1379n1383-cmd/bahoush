const crypto = require("crypto");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "Method Not Allowed"
    });
  }

  try {
    const {
      initData,
      title,
      description,
      contentType,
      contentUrl,
      publishAt
    } = req.body || {};

    if (!initData) {
      return res.status(400).json({
        ok: false,
        error: "initData ارسال نشده است"
      });
    }

    if (!title || !contentType) {
      return res.status(400).json({
        ok: false,
        error: "عنوان یا نوع محتوا مشخص نشده است"
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
      "Authorization": `Bearer ${supabaseSecretKey}`,
      "Content-Type": "application/json"
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
        error: "شما اجازه افزودن آموزش ندارید"
      });
    }

    // =========================
    // پیدا کردن شماره آموزش
    // =========================

    const orderUrl =
      `${supabaseUrl}/rest/v1/lessons` +
      `?select=sort_order` +
      `&order=sort_order.desc` +
      `&limit=1`;

    const orderResponse = await fetch(orderUrl, {
      method: "GET",
      headers
    });

    if (!orderResponse.ok) {
      console.error("Order Error:", await orderResponse.text());

      return res.status(500).json({
        ok: false,
        error: "خطا در دریافت شماره آموزش"
      });
    }

    const lastLessons = await orderResponse.json();

    const nextSortOrder =
      lastLessons.length > 0
        ? Number(lastLessons[0].sort_order || 0) + 1
        : 1;

    // =========================
    // ثبت آموزش
    // =========================

    const lessonData = {
      title: title.trim(),
      description: description ? description.trim() : "",
      sort_order: nextSortOrder,
      content_type: contentType,
      content_url: contentUrl || null,
      is_active: true,
      publish_at: publishAt || null
    };

    const lessonResponse = await fetch(
      `${supabaseUrl}/rest/v1/lessons`,
      {
        method: "POST",
        headers: {
          ...headers,
          "Prefer": "return=representation"
        },
        body: JSON.stringify(lessonData)
      }
    );

    if (!lessonResponse.ok) {
      console.error("Lesson Error:", await lessonResponse.text());

      return res.status(500).json({
        ok: false,
        error: "خطا در ثبت آموزش"
      });
    }

    const createdLesson = await lessonResponse.json();

    return res.status(200).json({
      ok: true,
      message: "آموزش با موفقیت ثبت شد",
      lesson: createdLesson[0]
    });

  } catch (error) {

    console.error("Create Lesson Error:", error);

    return res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور"
    });
  }
};
