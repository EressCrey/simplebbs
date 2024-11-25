package com.kkbbs.controller;

import com.kkbbs.annotation.GlobalInterceptor;
import com.kkbbs.annotation.VerifyParam;
import com.kkbbs.controller.base.BaseController;
import com.kkbbs.entity.query.UserInfoQuery;
import com.kkbbs.entity.vo.ResponseVO;
import com.kkbbs.service.UserInfoService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/user")
public class UserInfoController extends BaseController {

    @Resource
    private UserInfoService userInfoService;

    @RequestMapping("/loadUserList")
    @GlobalInterceptor
    public ResponseVO loadUserList(UserInfoQuery userInfoQuery) {
        userInfoQuery.setOrderBy("join_time desc");
        return getSuccessResponseVO(userInfoService.findListByPage(userInfoQuery));
    }


    @RequestMapping("/updateUserStatus")
    @GlobalInterceptor(checkParams = true)
    public ResponseVO updateUserStatus(@VerifyParam(required = true) Integer status, @VerifyParam(required = true) String userId) {
        userInfoService.updateUserStatus(status, userId);
        return getSuccessResponseVO(null);
    }

    @RequestMapping("/sendMessage")
    @GlobalInterceptor(checkParams = true)
    public ResponseVO sendMessage(@VerifyParam(required = true) String userId,
                                  @VerifyParam(required = true) String message,
                                  Integer integral) {
        userInfoService.sendMessage(userId, message, integral);
        return getSuccessResponseVO(null);
    }
}
