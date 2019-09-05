package com.businesssystemssecurity.proj.OCSP.client;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

@Configuration
@EnableScheduling
@Component
@EnableAsync
public class PeriodicOCSPValidator {

    private HashMap<String, CertStatus> certificatesInUse;
    private boolean systemReady = false;

    @Autowired
    private CertificateStorage certificateStorage;

    @Autowired
    private CertificateService certificateService;


    @PostConstruct
    public void init() {
        this.certificatesInUse = new HashMap<>();
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        this.systemReady = true;
    }

    public CertStatus checkCertificate(X509Certificate[] chain) throws CertificateException{
        if (chain == null) {
            throw new CertificateException("No certificates in the chain.");
        }

        String serialNumber = chain[0].getSerialNumber().toString();
        if (this.certificatesInUse.containsKey(serialNumber)) {
            return this.certificatesInUse.get(serialNumber);
        } else {
            return checkCertificateForced(chain);
        }
    }

    public CertStatus checkCertificateForced(X509Certificate[] chain) throws CertificateException{
        if (chain == null) {
            throw new CertificateException("No certificates in the chain.");
        }

        this.checkCertificateChain(chain);
        return this.certificatesInUse.get(chain[0].getSerialNumber().toString());
    }

    @Async
    @Scheduled(initialDelay = 1000 * 5, fixedDelay = 1000 * 45)
    void periodicValidation() {
        if (!this.systemReady) {
            return;
        }

        for (HashMap.Entry<String, CertStatus> entry : this.certificatesInUse.entrySet()) {
            Certificate c = this.certificateService.findBySerialNumber(entry.getKey());
            CertificatesAndKeyHolder ckh = this.certificateStorage.getPrivateKeyAndChain(c.getKeyStoreFilePath(), c.getSerialNumber());

            this.checkCertificateChain(ckh.getChain());
        }

        System.out.println("Periodic certificate check is done.");
    }

    private void checkCertificateChain(X509Certificate[] chain) {
        if (chain == null) {
            return;
        }

        String serialNumber = chain[0].getSerialNumber().toString();
        OCSPClient ocspClient = null;
        if (chain.length == 1) {
            ocspClient= new OCSPClient(chain[0], chain[0]);
        } else if (chain.length > 1) {
            ocspClient= new OCSPClient(chain[1], chain[0]);
        } else {
            this.certificatesInUse.put(serialNumber, CertStatus.UNKNOWN);
            return;
        }

        try {
            CertStatus certStatus = ocspClient.getCertificateStatus();
            this.certificatesInUse.put(serialNumber, certStatus);
        } catch (OCSPValidationException e) {
            e.printStackTrace();
        }
    }

}
