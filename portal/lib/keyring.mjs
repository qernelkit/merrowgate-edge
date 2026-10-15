// Depot vans hang their ignition keys in the cabinet by the gatehouse, one hook per van. The portal
// prints the hook labels: depot code, bay and fleet number, large enough to read at arm's length.
const FLEET_NUMBER = /^\d{3,5}$/;

export function keyringLabel(depot, bay, fleetNumber) {
  if (!FLEET_NUMBER.test(String(fleetNumber))) throw new RangeError(`not a fleet number: ${fleetNumber}`);
  return `${String(depot).toUpperCase()}-${String(bay).padStart(2, '0')}  VAN ${fleetNumber}`;
}

export function keyringSheet(depot, vans) {
  const rows = [...vans].sort((a, b) => Number(a.bay) - Number(b.bay));
  return rows.map((van) => keyringLabel(depot, van.bay, van.fleetNumber));
}
