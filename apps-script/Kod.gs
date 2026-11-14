/**
 * Commited Pasaport — yeni pasaport e-posta bildirimi
 *
 * Uygulama her yeni pasaportta Firestore'daki "mail" koleksiyonuna bir kayıt yazar.
 * Bu betik her dakika bu koleksiyonu okur, gönderilmemiş kayıtları commitedapp@gmail.com
 * hesabının Gmail'inden gönderir ve kaydı "delivered" olarak işaretler.
 *
 * Aynı tetikleyici, değişen pasaportları Commited adına imzalar (W3C Verifiable Credentials 2.0,
 * VC-JOSE: RS256 imzalı "vc+jwt"). İmzalı sürüm "credentials/{pasaportId}" belgesine yazılır;
 * pasaport sayfası bu imzayı .well-known/did.json içindeki açık anahtarla doğrular.
 * İmzalama, Komut dosyası özelliklerinde IMZA_ANAHTARI tanımlanınca başlar (admin paneli → İmza anahtarı).
 *
 * Kurulum (bir kez): kurulum() fonksiyonunu çalıştırın ve izinleri onaylayın.
 * Durdurmak için: durdur() fonksiyonunu çalıştırın.
 */

var PROJE = 'commited-pasaport';
var KOLEKSIYON = 'mail';
var IZINLI_ALICI = 'commitedapp@gmail.com'; // kurallar zaten bunu zorunlu kılıyor; burada da kontrol ediyoruz
var TABAN = 'https://firestore.googleapis.com/v1/projects/' + PROJE + '/databases/(default)/documents';

// İmza kimliği (did:web) — pasaport.commited.app alan adındaki /.well-known/did.json ile çözülür
var DID = 'did:web:pasaport.commited.app';
var KID = DID + '#key-1';
var PASAPORT_TABAN = 'https://pasaport.commited.app/';

function kurulum() {
  durdur();
  ScriptApp.newTrigger('herDakika').timeBased().everyMinutes(1).create();
  herDakika();
}

function durdur() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    var h = t.getHandlerFunction();
    if (h === 'bildirimleriGonder' || h === 'herDakika') ScriptApp.deleteTrigger(t);
  });
}

// her dakika: önce e-posta bildirimleri, sonra imzalama (biri hata verirse diğeri yine çalışır)
function herDakika() {
  try { bildirimleriGonder(); } catch (e) { console.error('Bildirim: ' + e); }
  try { pasaportlariImzala(); } catch (e) { console.error('İmza: ' + e); }
}

/* ---------------- Doğrulanabilir pasaport (W3C VC 2.0) ---------------- */

function pasaportlariImzala() {
  var ozellik = PropertiesService.getScriptProperties();
  var anahtar = ozellik.getProperty('IMZA_ANAHTARI');
  if (!anahtar) return; // anahtar henüz tanımlanmadı
  var pem = pemDuzelt_(anahtar);
  var kilit = LockService.getScriptLock();
  if (!kilit.tryLock(5000)) return;
  try {
    var imlec = ozellik.getProperty('IMZA_IMLEC') || '1970-01-01T00:00:00Z';
    var sorgu = {
      structuredQuery: {
        from: [{ collectionId: 'passports' }],
        where: { fieldFilter: { field: { fieldPath: 'updatedAt' }, op: 'GREATER_THAN_OR_EQUAL', value: { timestampValue: imlec } } },
        orderBy: [{ field: { fieldPath: 'updatedAt' }, direction: 'ASCENDING' }],
        limit: 50
      }
    };
    var belgeler = istek_('post', TABAN + ':runQuery', sorgu)
      .filter(function (r) { return r.document; })
      .map(function (r) { return r.document; });
    belgeler.forEach(function (doc) {
      var f = doc.fields || {};
      var guncel = f.updatedAt && f.updatedAt.timestampValue;
      if (!guncel) return;
      var id = doc.name.split('/').pop();
      var mevcut = belgeGetir_(TABAN + '/credentials/' + encodeURIComponent(id));
      var mf = (mevcut && mevcut.fields) || {};
      if (!(mf.passportUpdatedAt && mf.passportUpdatedAt.stringValue === guncel)) {
        var simdi = new Date().toISOString();
        var vc = vcOlustur_(id, f, guncel, simdi);
        var jwt = imzala_(vc, pem);
        istek_('patch', TABAN + '/credentials/' + encodeURIComponent(id), {
          fields: {
            jwt: { stringValue: jwt },
            kid: { stringValue: KID },
            passportUpdatedAt: { stringValue: guncel },
            signedAt: { timestampValue: simdi }
          }
        });
      }
      imlec = guncel;
    });
    ozellik.setProperty('IMZA_IMLEC', imlec);
  } finally {
    kilit.releaseLock();
  }
}

// Pasaportun herkese açık verisini W3C VC 2.0 zarfına koyar (otorite alanları dahil edilmez)
function vcOlustur_(id, f, guncel, simdi) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:' + Utilities.getUuid(),
    type: ['VerifiableCredential', 'DigitalProductPassportCredential'],
    name: 'Commited Digital Product Passport',
    issuer: { id: DID, name: 'Commited' },
    validFrom: simdi,
    credentialSubject: {
      id: PASAPORT_TABAN + '#p/' + id,
      type: 'Product',
      passportId: id,
      category: f.category ? fsDeger_(f.category) : '',
      manufacturer: f.company ? fsDeger_(f.company) : '',
      passportUpdatedAt: guncel,
      passportData: f.values ? fsDeger_(f.values) : {}
    }
  };
}

// VC-JOSE: başlık.yük.imza (RS256)
function imzala_(vc, pem) {
  var baslik = { alg: 'RS256', typ: 'vc+jwt', cty: 'vc', kid: KID };
  var girdi = b64u_(JSON.stringify(baslik)) + '.' + b64u_(JSON.stringify(vc));
  var imza = Utilities.computeRsaSha256Signature(girdi, pem, Utilities.Charset.UTF_8);
  return girdi + '.' + Utilities.base64EncodeWebSafe(imza).replace(/=+$/, '');
}

function b64u_(metin) {
  return Utilities.base64EncodeWebSafe(metin, Utilities.Charset.UTF_8).replace(/=+$/, '');
}

// Özellik kutusuna tek satır yapıştırılan PEM'i düzgün PEM biçimine getirir
function pemDuzelt_(s) {
  var govde = String(s).replace(/\\n/g, '\n').replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  return '-----BEGIN PRIVATE KEY-----\n' + govde.match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n';
}

// Firestore REST değerini düz JSON'a çevirir (tarayıcıdaki doğrulama ile aynı kurallar)
function fsDeger_(v) {
  if (v == null) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return Number(v.doubleValue);
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return Date.parse(v.timestampValue);
  if ('arrayValue' in v) return ((v.arrayValue && v.arrayValue.values) || []).map(fsDeger_);
  if ('mapValue' in v) {
    var o = {}, alanlar = (v.mapValue && v.mapValue.fields) || {};
    Object.keys(alanlar).forEach(function (k) { o[k] = fsDeger_(alanlar[k]); });
    return o;
  }
  if ('referenceValue' in v) return v.referenceValue;
  if ('geoPointValue' in v) return v.geoPointValue;
  return null;
}

function belgeGetir_(url) {
  var r = UrlFetchApp.fetch(url, {
    method: 'get',
    headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() },
    muteHttpExceptions: true
  });
  var kod = r.getResponseCode();
  if (kod === 404) return null;
  if (kod >= 300) throw new Error('Firestore ' + kod + ': ' + r.getContentText().slice(0, 300));
  return JSON.parse(r.getContentText() || '{}');
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
