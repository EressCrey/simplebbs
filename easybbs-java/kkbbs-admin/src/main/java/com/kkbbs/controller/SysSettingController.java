package com.kkbbs.controller;

import com.kkbbs.annotation.GlobalInterceptor;
import com.kkbbs.annotation.VerifyParam;
import com.kkbbs.controller.base.BaseController;
import com.kkbbs.entity.config.AdminConfig;
import com.kkbbs.entity.dto.*;
import com.kkbbs.entity.vo.ResponseVO;
import com.kkbbs.exception.BusinessException;
import com.kkbbs.service.SysSettingService;
import com.kkbbs.utils.JsonUtils;
import com.kkbbs.utils.OKHttpUtils;
import com.kkbbs.utils.StringTools;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/setting")
public class SysSettingController extends BaseController {
    @Resource
    private SysSettingService sysSettingService;

    @Resource
    private AdminConfig adminConfig;

    @RequestMapping("getSetting")
    public ResponseVO getSetting() {
        return getSuccessResponseVO(sysSettingService.refreshCache());
    }

    @RequestMapping("saveSetting")
    @GlobalInterceptor(checkParams = true)
    public ResponseVO saveSetting(@VerifyParam SysSetting4AuditDto auditDto,
                                  @VerifyParam SysSetting4CommentDto commentDto,
                                  @VerifyParam SysSetting4PostDto postDto,
                                  @VerifyParam SysSetting4LikeDto likeDto,
                                  @VerifyParam SysSetting4RegisterDto registerDto,
                                  @VerifyParam SysSetting4EmailDto emailDto) {
        SysSettingDto sysSettingDto = new SysSettingDto();
        sysSettingDto.setAuditStting(auditDto);
        sysSettingDto.setCommentSetting(commentDto);
        sysSettingDto.setPostSetting(postDto);
        sysSettingDto.setLikeSetting(likeDto);
        sysSettingDto.setEmailSetting(emailDto);
        sysSettingDto.setRegisterSetting(registerDto);
        sysSettingService.saveSetting(sysSettingDto);
        sendWebRequest();
        return getSuccessResponseVO(null);
    }

    private void sendWebRequest() {
        String appKey = adminConfig.getInnerApiAppKey();
        String appSecret = adminConfig.getInnerApiAppSecret();
        Long timestamp = System.currentTimeMillis();
        String sign = StringTools.encodeByMD5(appKey + timestamp + appSecret);
        String url = adminConfig.getWebApiUrl() + "?appKey=" + appKey + "&timestamp=" + timestamp + "&sign=" + sign;
        String responseJson = OKHttpUtils.getRequest(url);
        ResponseVO responseVO = JsonUtils.convertJson2Obj(responseJson, ResponseVO.class);
        if (!STATUC_SUCCESS.equals(responseVO.getStatus())) {
            throw new BusinessException("刷新访客端缓存失败");
        }
    }
}
