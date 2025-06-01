// routes/videoRoutes.js or routes/videoRoomRoutes.js
const express = require("express");
const router = express.Router();
const { createDailyRoom } = require("../controllers/VideoRoomController");

router.post("/create-room", createDailyRoom);

module.exports = router;
