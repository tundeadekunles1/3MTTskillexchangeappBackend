import axios from "axios";

export const createDailyRoom = async (startTime, durationMinutes = 120) => {
  const exp =
    Math.floor(new Date(startTime).getTime() / 1000) + durationMinutes * 60;

  const res = await axios.post(
    "https://api.daily.co/v1/rooms",
    {
      properties: {
        enable_prejoin_ui: true,
        exp,
      },
    },
    {
      headers: {
        Authorization: `Bearer ${process.env.DAILY_API_KEY}`,
      },
    }
  );

  return res.data.url;
};
