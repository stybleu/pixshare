/* PixShare : filtres photo des membres. MÊMES formules que pixshare/services/photo_filter_service.py,
   pour que l'aperçu corresponde exactement à l'image envoyée. */
(function () {
  "use strict";
  var FILTERS = {
    noir_blanc: { ops: [["grayscale", 1.0], ["contrast", 1.05]] },
    dramatique: { ops: [["grayscale", 1.0], ["contrast", 1.6], ["brightness", 0.95]] },
    retro: { ops: [["sepia", 0.85], ["contrast", 1.05], ["brightness", 1.02]] },
    vintage: { ops: [["sepia", 0.4], ["saturate", 0.8], ["contrast", 0.9], ["brightness", 1.06]], vignette: 0.45 },
    intense: { ops: [["contrast", 1.25], ["saturate", 1.7]] },
    chaud: { ops: [["saturate", 1.15], ["brightness", 1.04]], tint: [[255, 214, 170], 0.35] },
    froid: { ops: [["saturate", 0.95], ["brightness", 1.06]], tint: [[170, 205, 255], 0.35] },
    doux: { ops: [["brightness", 1.08], ["contrast", 0.88], ["saturate", 0.9]] }
  };

  function matrix(op, amount) {
    var a = 1 - amount, s = amount, c, n;
    if (op === "grayscale") return [
      0.2126 + 0.7874 * a, 0.7152 - 0.7152 * a, 0.0722 - 0.0722 * a,
      0.2126 - 0.2126 * a, 0.7152 + 0.2848 * a, 0.0722 - 0.0722 * a,
      0.2126 - 0.2126 * a, 0.7152 - 0.7152 * a, 0.0722 + 0.9278 * a];
    if (op === "sepia") return [
      0.393 + 0.607 * a, 0.769 - 0.769 * a, 0.189 - 0.189 * a,
      0.349 - 0.349 * a, 0.686 + 0.314 * a, 0.168 - 0.168 * a,
      0.272 - 0.272 * a, 0.534 - 0.534 * a, 0.131 + 0.869 * a];
    if (op === "saturate") return [
      0.213 + 0.787 * s, 0.715 - 0.715 * s, 0.072 - 0.072 * s,
      0.213 - 0.213 * s, 0.715 + 0.285 * s, 0.072 - 0.072 * s,
      0.213 - 0.213 * s, 0.715 - 0.715 * s, 0.072 + 0.928 * s];
    if (op === "hue") {
      c = Math.cos(amount * Math.PI / 180); n = Math.sin(amount * Math.PI / 180);
      return [
        0.213 + c * 0.787 - n * 0.213, 0.715 - c * 0.715 - n * 0.715, 0.072 - c * 0.072 + n * 0.928,
        0.213 - c * 0.213 + n * 0.143, 0.715 + c * 0.285 + n * 0.140, 0.072 - c * 0.072 - n * 0.283,
        0.213 - c * 0.213 - n * 0.787, 0.715 - c * 0.715 + n * 0.715, 0.072 + c * 0.928 + n * 0.072];
    }
    return null;
  }
  function scaled(op, value, t) { return (op === "grayscale" || op === "sepia" || op === "hue") ? value * t : 1 + (value - 1) * t; }
  function clamp(x) { return x < 0 ? 0 : (x > 1 ? 1 : x); }

  /* Applique le filtre sur un ImageData (modifié sur place). */
  function apply(imageData, name, strength) {
    var spec = FILTERS[name], t = Math.max(0, Math.min(100, strength | 0)) / 100;
    if (!spec || t <= 0) return imageData;
    var steps = spec.ops.map(function (o) { var amt = scaled(o[0], o[1], t); return [o[0], amt, matrix(o[0], amt)]; });
    var tint = null, vig = 0;
    if (spec.tint) { var k = spec.tint[1] * t; tint = spec.tint[0].map(function (c) { return 1 - k + k * c / 255; }); }
    if (spec.vignette) vig = spec.vignette * t;
    var d = imageData.data, w = imageData.width, h = imageData.height;
    for (var y = 0; y < h; y++) {
      for (var x = 0; x < w; x++) {
        var i = (y * w + x) * 4, r = d[i] / 255, g = d[i + 1] / 255, b = d[i + 2] / 255;
        for (var s = 0; s < steps.length; s++) {
          var op = steps[s][0], m = steps[s][2], v = steps[s][1];
          if (m) {
            var nr = m[0] * r + m[1] * g + m[2] * b, ng = m[3] * r + m[4] * g + m[5] * b, nb = m[6] * r + m[7] * g + m[8] * b;
            r = nr; g = ng; b = nb;
          } else if (op === "brightness") { r *= v; g *= v; b *= v; }
          else if (op === "contrast") { r = (r - 0.5) * v + 0.5; g = (g - 0.5) * v + 0.5; b = (b - 0.5) * v + 0.5; }
          r = clamp(r); g = clamp(g); b = clamp(b);
        }
        if (tint) { r *= tint[0]; g *= tint[1]; b *= tint[2]; }
        if (vig) {
          var dx = (x + 0.5 - w / 2) / (w / 2), dy = (y + 0.5 - h / 2) / (h / 2);
          var dist = Math.sqrt(dx * dx + dy * dy) / Math.SQRT2, al = vig * Math.max(0, Math.min(1, (dist - 0.55) / 0.45));
          r *= 1 - al; g *= 1 - al; b *= 1 - al;
        }
        d[i] = Math.round(clamp(r) * 255); d[i + 1] = Math.round(clamp(g) * 255); d[i + 2] = Math.round(clamp(b) * 255);
      }
    }
    return imageData;
  }

  window.PixFilters = { names: Object.keys(FILTERS), apply: apply };
})();
