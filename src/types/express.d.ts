declare namespace Express {
    interface User {
      id: string;
      username?: string;
      fullName: string;
      email: string;
      profileImage?: string;
      provider?: string;
    }
  }