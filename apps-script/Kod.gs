/**
 * Commited Pasaport — yeni pasaport e-posta bildirimi
 *
 * Uygulama her yeni pasaportta Firestore'daki "mail" koleksiyonuna bir kayıt yazar.
 * Bu betik her dakika bu koleksiyonu okur, gönderilmemiş kayıtları commitedapp@gmail.com
 * hesabının Gmail'inden gönderir ve kaydı "delivered" olarak işaretler.
 *
 * Kurulum (bir kez): kurulum() fonksiyonunu çalıştırın ve izinleri onaylayın.
 * Durdurmak için: durdur() fonksiyonunu çalıştırın.
 */

var PROJE = 'commited-pasaport';
var KOLEKSIYON = 'mail';
var IZINLI_ALICI = 'commitedapp@gmail.com'; // kurallar zaten bunu zorunlu kılıyor; burada da kontrol ediyoruz
var TABAN = 'https://firestore.googleapis.com/v1/projects/' + PROJE + '/databases/(default)/documents';

function kurulum() {
  durdur();
  ScriptApp.newTrigger('bildirimleriGonder').timeBased().everyMinutes(1).create();
  bildirimleriGonder();
}

function durdur() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'bildirimleriGonder') ScriptApp.deleteTrigger(t);
  });
}

function bildirimleriGonder() {
  var kilit = LockService.getScriptLock();
  if (!kilit.tryLock(5000)) return;
  try {
    var kayitlar = bekleyenler_();
    kayitlar.forEach(function (doc) {
      var f = doc.fields || {};
      var alicilar = (((f.to || {}).arrayValue || {}).values || []).map(function (v) { return v.stringValue; });
      var mesaj = ((f.message || {}).mapValue || {}).fields || {};
      var konu = (mesaj.subject || {}).stringValue || 'Yeni ürün pasaportu';
      var html = (mesaj.html || {}).stringValue || '';
      if (alicilar.length !== 1 || alicilar[0] !== IZINLI_ALICI) {
        isaretle_(doc.name, 'skipped');
        return;
      }
      MailApp.sendEmail({ to: IZINLI_ALICI, subject: konu, htmlBody: html, name: 'Commited Pasaport' });
      isaretle_(doc.name, 'delivered');
    });
  } finally {
    kilit.releaseLock();
  }
}

// state alanı olmayan (henüz işlenmemiş) kayıtları bulur
function bekleyenler_() {
  var sorgu = {
    structuredQuery: {
      from: [{ collectionId: KOLEKSIYON }],
      orderBy: [{ field: { fieldPath: 'createdAt' }, direction: 'DESCENDING' }],
      limit: 50
    }
  };
  var cevap = istek_('post', TABAN + ':runQuery', sorgu);
  return cevap
    .filter(function (r) { return r.document; })
    .map(function (r) { return r.document; })
    .filter(function (d) { return !(d.fields && d.fields.state); });
}

function isaretle_(ad, durum) {
  var url = 'https://firestore.googleapis.com/v1/' + ad +
    '?updateMask.fieldPaths=state&updateMask.fieldPaths=processedAt';
  istek_('patch', url, {
    fields: {
      state: { stringValue: durum },
      processedAt: { timestampValue: new Date().toISOString() }
    }
  });
}

function istek_(yontem, url, govde) {
  var r = UrlFetchApp.fetch(url, {
    method: yontem,
    contentType: 'application/json',
    headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() },
    payload: JSON.stringify(govde),
    muteHttpExceptions: true
  });
  var kod = r.getResponseCode();
  if (kod >= 300) throw new Error('Firestore ' + kod + ': ' + r.getContentText().slice(0, 300));
  return JSON.parse(r.getContentText() || '{}');
}
