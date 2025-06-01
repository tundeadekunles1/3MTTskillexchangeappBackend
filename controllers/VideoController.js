import axios from "axios";

export async function createDailyRoom(startTime, durationMinutes = 120) {
  // Validate environment variable
  if (!process.env.DAILYCO_API_KEY) {
    throw new Error("DAILYCO_API_KEY environment variable is not set");
  }

  // Validate durationMinutes
  if (durationMinutes <= 0 || durationMinutes > 1440) {
    throw new Error("durationMinutes must be between 1 and 1440 (24 hours)");
  }

  // Validate startTime
  const startDate = new Date(startTime);
  if (isNaN(startDate.getTime())) {
    throw new Error("Invalid startTime provided");
  }

  const nowUnix = Math.floor(Date.now() / 1000);
  const startTimeUnix = Math.floor(startDate.getTime() / 1000);
  if (startTimeUnix < nowUnix) {
    throw new Error("startTime must be in the future");
  }

  const endTimeUnix = startTimeUnix + durationMinutes * 60;

  try {
    const res = await axios.post(
      "https://api.daily.co/v1/rooms",
      {
        properties: {
          enable_prejoin_ui: true,
          exp: endTimeUnix,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.DAILYCO_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    if (!res.data.url) {
      throw new Error("Failed to retrieve room URL from Daily API");
    }

    return res.data.url;
  } catch (error) {
    const errorMessage = error.response?.data?.error || error.message;
    console.error("Failed to create Daily room:", errorMessage);
    throw new Error(`Daily API error: ${errorMessage}`);
  }
}
