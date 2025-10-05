import type { Request, Response, NextFunction } from "express";
import prisma from "../lib/prisma.js";
import { verifyAccessToken } from "../lib/token.js";
import { ACCESS_TOKEN_COOKIE_NAME } from "../lib/constants.js";

interface AuthOptions {
  optional?: boolean;
}

function authenticate(options: AuthOptions = { optional: false }) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    // access token
    // 클라이언트에서는 로컬 스토리지에서 다루기 서버로 요청 보낼때는 authorization header에 담아서 보내기
    // ttl 짧기 때문에 괜찮음...
    // refresh token 쿠키 + 쿠키 설정(secure, httpOnly, sameSite)

    // jwt 방식의 로그인은 유저의 로그인 상태를 서버가 저장하지 않음
    // 세션방식의 로그인은 서버가 유저의 로그인 상태를 가지고 있음.

    // 액세스 토큰만 다루고 expiration 30분일 경우...
    // 세션 방식 유저의 로그인 정보를 서버가 들고있는거임...(user1은 연결된 상태고, 30분동안 요청이 없을 경우 재 로그인을 요청한다.)

    const accessToken = req.cookies?.[ACCESS_TOKEN_COOKIE_NAME];

    if (!accessToken) {
      if (options.optional) {
        return next();
      }
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    try {
      const { userId } = verifyAccessToken(accessToken);
      const user = await prisma.user.findUnique({ where: { id: userId } });
      req.user = user;
    } catch (error) {
      if (options.optional) {
        return next();
      }
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    next();
  };
}

export default authenticate;
