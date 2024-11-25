package com.kkbbs.controller;

import com.kkbbs.annotation.GlobalInterceptor;
import com.kkbbs.annotation.VerifyParam;
import com.kkbbs.controller.base.BaseController;
import com.kkbbs.entity.config.AdminConfig;
import com.kkbbs.entity.constants.Constants;
import com.kkbbs.entity.dto.CreateImageCode;
import com.kkbbs.entity.dto.SessionAdminUserDto;
import com.kkbbs.entity.vo.ResponseVO;
import com.kkbbs.exception.BusinessException;
import com.kkbbs.utils.StringTools;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@RestController
public class LoginController extends BaseController {

    @Resource
    private AdminConfig adminConfig;


    /**
     * 验证码
     * @param request
     * @param response
     * @param session
     * @param type
     * @throws IOException
     */
    @RequestMapping(value = "/checkCode")
    public void checkCode(HttpServletRequest request, HttpServletResponse response, HttpSession session,Integer type) throws
            IOException {
        CreateImageCode vCode = new CreateImageCode(130, 38, 4, 10);
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache");
        response.setDateHeader("Expires", 0);
        response.setContentType("image/jpeg");
        String code = vCode.getCode();
        session.setAttribute(Constants.CHECK_CODE_KEY, code);
        vCode.write(response.getOutputStream());
       /* String code = vCode.getCode();
        if (type == null || type == 0) {
            session.setAttribute(Constants.CHECK_CODE_KEY, code);
        } else {
            session.setAttribute(Constants.CHECK_CODE_KEY_EMAIL, code);
        }
        vCode.write(response.getOutputStream());*/
    }

    /**
     * @Description: 登录
     * @auther: laoluo
     * @date: 17:34 2022/11/20
     * @param: [session, account, password, checkCode]
     * @return: com.kkbbs.entity.vo.ResponseVO
     */
    @RequestMapping("/login")
    @GlobalInterceptor(checkParams = true)
    public ResponseVO login(HttpSession session,
                            @VerifyParam(required = true) String account,
                            @VerifyParam(required = true) String password,
                            @VerifyParam(required = true) String checkCode) {
        try {
            if (!checkCode.equalsIgnoreCase((String) session.getAttribute(Constants.CHECK_CODE_KEY))) {
                throw new BusinessException("图片验证码不正确");
            }

            if (!adminConfig.getAdminAccount().equals(account) || !StringTools.encodeByMD5(adminConfig.getAdminPassword()).equals(password)) {
                throw new BusinessException("账号或密码错误");
            }
            SessionAdminUserDto sessionAdminUserDto = new SessionAdminUserDto();
            sessionAdminUserDto.setAccount(account);
            session.setAttribute(Constants.SESSION_KEY, sessionAdminUserDto);
            return getSuccessResponseVO(sessionAdminUserDto);
        } finally {
            session.removeAttribute(Constants.CHECK_CODE_KEY);

        }
    }
}
