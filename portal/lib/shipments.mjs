// Shipment statuses as the depot floor uses them. A cage is "sealed" once its tamper seal is fitted and
// photographed; the receiving depot checks the seal number again before it is opened.
export const SEALED_SHIPMENT = 'sealed';

export const SHIPMENT_STATUSES = ['booked', 'picked', SEALED_SHIPMENT, 'loaded', 'departed', 'delivered', 'exception'];

const NEXT = {
  booked: ['picked', 'exception'],
  picked: [SEALED_SHIPMENT, 'exception'],
  [SEALED_SHIPMENT]: ['loaded', 'exception'],
  loaded: ['departed', 'exception'],
  departed: ['delivered', 'exception'],
  delivered: [],
  exception: ['picked'],
};

export function canMove(from, to) {
  return (NEXT[from] ?? []).includes(to);
}

export function applyStatus(shipment, status, actor, sealNumber) {
  if (!canMove(shipment.status, status)) {
    throw new RangeError(`a ${shipment.status} shipment cannot become ${status}`);
  }
  if (status === SEALED_SHIPMENT && !/^\d{7,10}$/.test(String(sealNumber ?? ''))) {
    throw new RangeError('a seal number is needed to mark the cage sealed');
  }
  const history = [...(shipment.history ?? []), { status, actor, at: new Date().toISOString() }];
  return { ...shipment, status, sealNumber: sealNumber ?? shipment.sealNumber ?? null, history };
}
