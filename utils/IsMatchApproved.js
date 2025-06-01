const isMatchApproved = async (userId1, userId2, MatchRequestModel) => {
  return await MatchRequestModel.findOne({
    $or: [
      { teacherId: userId1, learnerId: userId2 },
      { teacherId: userId2, learnerId: userId1 },
    ],
    status: "approved",
  });
};

module.exports = isMatchApproved;
