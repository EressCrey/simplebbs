package com.kkbbs.controller.api;

import com.kkbbs.annotation.GlobalInterceptor;
import com.kkbbs.annotation.VerifyParam;
import com.kkbbs.controller.base.BaseController;
import com.kkbbs.entity.config.WebConfig;
import com.kkbbs.entity.enums.ResponseCodeEnum;
import com.kkbbs.entity.vo.ResponseVO;
import com.kkbbs.exception.BusinessException;
import com.kkbbs.service.SysSettingService;
import com.kkbbs.utils.StringTools;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/innerApi")
public class InnnerApiController extends BaseController {

    @Resource
    private WebConfig webConfig;

    @Resource
    private SysSettingService sysSettingService;

    @RequestMapping("/refresSysSetting")
    @GlobalInterceptor(checkParams = true)
    public ResponseVO refresSysSetting(@VerifyParam(required = true) String appKey,
                                       @VerifyParam(required = true) Long timestamp,
                                       @VerifyParam(required = true) String sign) {
        if (!webConfig.getInnerApiAppKey().equals(appKey)) {
            throw new BusinessException(ResponseCodeEnum.CODE_600);
        }

        if (System.currentTimeMillis() - timestamp > 1000 * 10) {
            throw new BusinessException(ResponseCodeEnum.CODE_600);
        }
        String mySign = StringTools.encodeByMD5(appKey + timestamp + webConfig.getInnerApiAppSecret());
        if (!mySign.equals(sign)) {
            throw new BusinessException(ResponseCodeEnum.CODE_600);
        }
        return getSuccessResponseVO(sysSettingService.refreshCache());
    }
}
