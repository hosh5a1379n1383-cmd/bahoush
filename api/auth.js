module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "Method Not Allowed"
    });
  }

  return res.status(200).json({
    ok: true,
    message: "ارتباط با سرور برقرار است ✅"
  });
};
