const ECKEM = require('./eckem');
const iota = require('./iota');
const TKEM = require('./TKEM');

window.TKEM = {
  ECKEM: ECKEM,
  iota: iota,
  TKEM: TKEM,
}
