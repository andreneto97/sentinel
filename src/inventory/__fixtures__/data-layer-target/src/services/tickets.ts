import { getRepository } from "typeorm";

/** The entity the fixture repository is typed with. */
export class Ticket {}

/** One owner's tickets, read through the repository API. */
export async function ticketsFor(ownerId: string) {
  const ticketRepository = getRepository(Ticket);
  return await ticketRepository.find({ where: { ownerId }, take: 25, select: { id: true } });
}

/** Every ticket, read through the query builder with no predicate. */
export async function allTickets() {
  const ticketRepository = getRepository(Ticket);
  return await ticketRepository.createQueryBuilder("ticket").getMany();
}
