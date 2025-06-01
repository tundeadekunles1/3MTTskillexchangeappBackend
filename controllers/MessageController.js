import Message from "../models/Message";
import MatchRequest from "../models/MatchRequest";
import isMatchApproved from "../utils/isMatchApproved";

export const sendMessage = async (req, res) => {
  try {
    const { senderId, receiverId, text, attachmentUrl } = req.body;

    const approved = await isMatchApproved(senderId, receiverId, MatchRequest);
    if (!approved) {
      return res
        .status(403)
        .json({ message: "Users are not approved to chat." });
    }

    const newMessage = new Message({
      senderId,
      receiverId,
      text,
      attachmentUrl,
      timestamp: new Date(),
    });

    await newMessage.save();
    res.status(201).json(newMessage);
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({ message: "Server error sending message" });
  }
};

export const getConversation = async (req, res) => {
  const { userId1, userId2 } = req.params;

  try {
    const messages = await Message.find({
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 },
      ],
    }).sort({ timestamp: 1 });

    res.status(200).json(messages);
  } catch (err) {
    console.error("Fetch conversation error:", err);
    res.status(500).json({ message: "Server error fetching messages" });
  }
};
