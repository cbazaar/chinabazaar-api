// Paylaşılan doğrulama yardımcısı — express-validator sonuçlarını tek tip döndürür.
const { validationResult } = require('express-validator');

function checkValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ error: 'validation_failed', details: errors.array() });
    return false;
  }
  return true;
}

module.exports = { checkValidation };
