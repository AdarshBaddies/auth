import mongoose from "mongoose";

const connectToDatabase = async (mongoUri) => {
  if (!mongoUri) {
    throw new Error("MONGODB_URI is not defined");
  }
  mongoose.set("strictQuery", true);
  await mongoose.connect(mongoUri, {
    autoIndex: true,
  });
  return mongoose.connection;
};

export default connectToDatabase;

