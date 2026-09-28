import mongoose from "mongoose";

/** The fixture model. */
export const MessageModel = mongoose.model("Message", new mongoose.Schema({}));

/** One conversation's messages, bounded. */
export async function messagesIn(conversationId: string) {
  return await MessageModel.find({ conversationId }).limit(50);
}

/** Every message in the collection. */
export async function allMessages() {
  return await MessageModel.find({});
}
